/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors.RevocationMode;
import io.helixiam.common.log.LogSafe;
import io.helixiam.common.net.OutboundUrlGuard;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;

/**
 * Validates a credential issuer's certificate chain (leaf first, as carried in an SD-JWT VC {@code x5c} header or an
 * mdoc {@code x5chain}) against the trust anchors configured for a wallet provider, at a given instant.
 *
 * <p>Checks, in order (all failures are {@link WalletVerificationException}s with a safe detail):
 * <ol>
 *   <li>the chain is non-empty ({@code ISSUER_UNTRUSTED}) and at most {@value #MAX_CHAIN_LENGTH} certificates
 *       ({@code LIMIT_EXCEEDED});</li>
 *   <li>the leaf is not self-signed (HAIP: "The X.509 certificate signing the request MUST NOT be self-signed"), even
 *       when it is itself configured as an anchor;</li>
 *   <li>trailing certificates that are configured anchors are stripped (HAIP forbids the anchor in {@code x5c}, but
 *       real issuers send it; tolerating it is harmless because the anchor comes from configuration, not the chain),
 *       and a chain that stops short of an anchor is completed from the pinned intermediates;</li>
 *   <li>every non-anchor key is EC P-256/P-384/P-521 or RSA &ge; 2048 ({@code ALGORITHM_NOT_ALLOWED});</li>
 *   <li>the leaf has a key-usage extension with {@code digitalSignature} set. The ETSI PID-provider certificate
 *       profile is UNVERIFIED (docs/eudi-wallet-spec-notes.md §9.4), so this is the conservative minimum: an issuer
 *       signing certificate must be allowed to sign. Extended key usage is not checked;</li>
 *   <li>JDK {@code CertPathValidator("PKIX")} with {@code PKIXParameters.setDate(at)}: signatures, validity
 *       ({@code ISSUER_UNTRUSTED} "certificate expired" / "certificate not yet valid"), CA basic constraints, name
 *       chaining and, per {@link RevocationMode}, revocation.</li>
 * </ol>
 *
 * <p><b>Revocation</b> runs as a second PKIX pass, only after the first pass (no revocation) has proven the chain
 * reaches an anchor at {@code at}, so every second-pass failure is a revocation outcome. {@code OFF}: no revocation
 * check and no network access. {@code HARD_FAIL}: the JDK {@link PKIXRevocationChecker} (OCSP preferred, CRL
 * distribution point fallback) must establish a good status for every certificate below the anchor, otherwise
 * "certificate revocation status unavailable". {@code SOFT_FAIL}: {@link PKIXRevocationChecker.Option#SOFT_FAIL};
 * an undeterminable status (unreachable responder, or no responder / distribution point at all, which the JDK's own
 * soft-fail does not cover) passes and is logged as a warning carrying only that certificate's serial and subject DN.
 * A {@code REVOKED} answer fails in both modes ("certificate revoked"). The leaf is checked on its own first, then the
 * CA certificates below the anchor together, so an undeterminable CA never hides the leaf's status. Known limit: under
 * SOFT_FAIL, an undeterminable upper CA stops the JDK before it checks a lower CA (only with two or more
 * intermediates).
 *
 * <p><b>SSRF (security concern).</b> The CRL distribution point and OCSP AIA URLs come from the presented,
 * attacker-supplied certificates, and the JDK fetches them itself. Mitigations here: (1) nothing is fetched unless
 * the chain already validates to a configured anchor, so only certificates a trusted CA issued can steer a fetch;
 * (2) every such URL first passes {@link OutboundUrlGuard}: a non-http(s) scheme ({@code ldap:}, {@code file:} ...),
 * a non-URI name, or a host resolving to a loopback / private / link-local address is never fetched
 * ({@code HARD_FAIL}: rejected with "revocation endpoint not allowed"; {@code SOFT_FAIL}: revocation is skipped for
 * this chain with a warning). Residual risks not closed here: DNS rebinding between the guard's resolution and the
 * JDK's; HTTP redirects followed by the JDK's {@code HttpURLConnection}; the JDK-global timeouts
 * ({@code com.sun.security.ocsp.timeout}, {@code com.sun.security.crl.timeout}; bounded to 3 s connect / 5 s read by
 * {@code RevocationTimeouts} in {@code main}) and the unbounded CRL download size. A guarded, size- and time-bounded revocation client is the real fix (follow-up).
 */
public final class IssuerTrustValidator {

    private static final Logger LOG = LogManager.getLogger(IssuerTrustValidator.class);

    /** The longest {@code x5c} / {@code x5chain} accepted (after pinned intermediates are added). */
    static final int MAX_CHAIN_LENGTH = 10;
    private static final int MIN_RSA_BITS = 2048;
    private static final List<ECParameterSpec> ALLOWED_CURVES =
            List.of(curve("secp256r1"), curve("secp384r1"), curve("secp521r1"));

    private final OutboundUrlGuard guard;

    /** Production default: revocation URLs pass the environment-configured (block-private) outbound guard. */
    public IssuerTrustValidator() {
        this(new OutboundUrlGuard());
    }

    public IssuerTrustValidator(final OutboundUrlGuard guard) {
        this.guard = Objects.requireNonNull(guard, "guard");
    }

    /** Validates leaf-first chain (as in x5c / x5chain) to a configured anchor at {@code at}; returns the leaf. */
    public X509Certificate validate(final List<X509Certificate> chain, final TrustAnchors anchors, final Instant at) {
        Objects.requireNonNull(anchors, "anchors");
        Objects.requireNonNull(at, "at");
        if (chain == null || chain.isEmpty() || chain.stream().anyMatch(Objects::isNull)) {
            throw untrusted("empty certificate chain");
        }
        if (chain.size() > MAX_CHAIN_LENGTH) {
            throw new WalletVerificationException(WalletErrorCode.LIMIT_EXCEEDED, "certificate chain too long");
        }
        if (anchors.anchors().isEmpty()) {
            throw untrusted("no trust anchors configured");
        }
        final X509Certificate leaf = chain.get(0);
        if (isSelfSigned(leaf)) {
            throw untrusted("leaf certificate is self-signed");
        }
        final List<X509Certificate> path = completeWithPinned(stripAnchors(chain, anchors), anchors);
        for (final X509Certificate cert : path) {
            checkKey(cert.getPublicKey());
        }
        final boolean[] keyUsage = leaf.getKeyUsage();
        if (keyUsage == null || keyUsage.length == 0 || !keyUsage[0]) {
            throw untrusted("leaf certificate lacks digitalSignature key usage");
        }
        validatePath(path, anchors, at, leaf);
        return leaf;
    }

    private void validatePath(final List<X509Certificate> path, final TrustAnchors anchors, final Instant at,
            final X509Certificate leaf) {
        final CertPath certPath;
        final CertPathValidator validator;
        try {
            certPath = CertificateFactory.getInstance("X.509").generateCertPath(path);
            validator = CertPathValidator.getInstance("PKIX");
        } catch (final GeneralSecurityException e) {
            throw untrusted("certificate chain not trusted");
        }
        // Pass 1: the full path check without revocation. No network access happens before the chain is proven to
        // reach a configured anchor, so a forged chain can never make the server fetch its CRL / OCSP URLs.
        try {
            validator.validate(certPath, parameters(anchors, at));
        } catch (final CertPathValidatorException e) {
            throw mapFailure(e);
        } catch (final GeneralSecurityException e) {
            throw untrusted("certificate chain not trusted");
        }
        final RevocationMode mode = anchors.revocation(); // never null: TrustAnchors defaults it to SOFT_FAIL
        if (mode == RevocationMode.OFF) {
            return;
        }
        if (!revocationEndpointsAllowed(path)) {
            if (mode == RevocationMode.HARD_FAIL) {
                throw untrusted("revocation endpoint not allowed");
            }
            warn("revocation endpoint not allowed", leaf);
            return;
        }
        // Pass 2: revocation only. The path is valid, so every failure here is a revocation outcome. The leaf is
        // checked on its own first (ONLY_END_ENTITY), then the CA certificates below the anchor in one pass: the JDK
        // checks anchor-side first and stops at the first undeterminable certificate, so a single pass over the whole
        // path could leave the leaf unchecked under SOFT_FAIL. The JDK treats ONLY_END_ENTITY as "skip CA
        // certificates", so a leaf that is (oddly) a CA is checked with the whole path instead.
        checkRevocation(validator, path, anchors, at, mode, leaf.getBasicConstraints() < 0);
        if (path.size() > 1) {
            checkRevocation(validator, path.subList(1, path.size()), anchors, at, mode, false);
        }
    }

    /**
     * Revocation status of {@code suffix.get(0)} only ({@code endEntityOnly}; the JDK skips CA certificates with that
     * option, so it is used for the leaf alone), or of every certificate in {@code suffix} (the CA part of the path).
     * A suffix of a valid path is itself a valid path.
     */
    private static void checkRevocation(final CertPathValidator validator, final List<X509Certificate> suffix,
            final TrustAnchors anchors, final Instant at, final RevocationMode mode, final boolean endEntityOnly) {
        try {
            final CertPath certPath = CertificateFactory.getInstance("X.509").generateCertPath(suffix);
            final PKIXParameters params = parameters(anchors, at);
            final PKIXRevocationChecker checker = (PKIXRevocationChecker) validator.getRevocationChecker();
            final EnumSet<PKIXRevocationChecker.Option> options = EnumSet.noneOf(PKIXRevocationChecker.Option.class);
            if (endEntityOnly) {
                options.add(PKIXRevocationChecker.Option.ONLY_END_ENTITY);
            }
            if (mode == RevocationMode.SOFT_FAIL) {
                options.add(PKIXRevocationChecker.Option.SOFT_FAIL);
            }
            checker.setOptions(options);
            params.setRevocationEnabled(true);
            params.addCertPathChecker(checker);
            validator.validate(certPath, params);
            if (!checker.getSoftFailExceptions().isEmpty()) {
                warn("revocation status unavailable", suffix.get(0));
            }
        } catch (final CertPathValidatorException e) {
            if (e.getReason() == CertPathValidatorException.BasicReason.REVOKED) {
                throw untrusted("certificate revoked");
            }
            final int index = e.getIndex();
            undetermined(mode, suffix.get(index >= 0 && index < suffix.size() ? index : 0));
        } catch (final GeneralSecurityException e) {
            undetermined(mode, suffix.get(0));
        }
    }

    /**
     * HARD_FAIL rejects; SOFT_FAIL accepts with a warning. The JDK's own soft-fail covers network errors only; a
     * certificate without any responder or distribution point is equally undeterminable, so it is treated the same.
     */
    private static void undetermined(final RevocationMode mode, final X509Certificate cert) {
        if (mode == RevocationMode.HARD_FAIL) {
            throw untrusted("certificate revocation status unavailable");
        }
        warn("revocation status unavailable", cert);
    }

    private static PKIXParameters parameters(final TrustAnchors anchors, final Instant at)
            throws GeneralSecurityException {
        final PKIXParameters params = new PKIXParameters(anchors.anchors());
        params.setDate(Date.from(at));
        params.setRevocationEnabled(false);
        return params;
    }

    private static WalletVerificationException mapFailure(final CertPathValidatorException e) {
        final CertPathValidatorException.Reason reason = e.getReason();
        if (reason == CertPathValidatorException.BasicReason.EXPIRED) {
            return untrusted("certificate expired");
        }
        if (reason == CertPathValidatorException.BasicReason.NOT_YET_VALID) {
            return untrusted("certificate not yet valid");
        }
        if (reason == CertPathValidatorException.BasicReason.ALGORITHM_CONSTRAINED) {
            return new WalletVerificationException(WalletErrorCode.ALGORITHM_NOT_ALLOWED,
                    "certificate algorithm not allowed");
        }
        return untrusted("certificate chain not trusted");
    }

    /** Drops trailing certificates that are configured anchors (never the leaf). */
    private static List<X509Certificate> stripAnchors(final List<X509Certificate> chain, final TrustAnchors anchors) {
        final List<X509Certificate> path = new ArrayList<>(chain);
        while (path.size() > 1 && isAnchor(path.get(path.size() - 1), anchors)) {
            path.remove(path.size() - 1);
        }
        return path;
    }

    /** Appends pinned intermediates while the chain's top certificate is not issued by an anchor. */
    private static List<X509Certificate> completeWithPinned(final List<X509Certificate> path,
            final TrustAnchors anchors) {
        while (path.size() < MAX_CHAIN_LENGTH) {
            final X509Certificate top = path.get(path.size() - 1);
            if (issuedByAnchor(top, anchors)) {
                break;
            }
            final X509Certificate next = anchors.pinnedIntermediates().stream()
                    .filter(p -> !path.contains(p))
                    .filter(p -> p.getSubjectX500Principal().equals(top.getIssuerX500Principal()))
                    .filter(p -> verifies(top, p.getPublicKey()))
                    .findFirst().orElse(null);
            if (next == null) {
                break;
            }
            path.add(next);
        }
        return path;
    }

    private static boolean isAnchor(final X509Certificate cert, final TrustAnchors anchors) {
        return anchors.anchors().stream().map(TrustAnchor::getTrustedCert).anyMatch(cert::equals);
    }

    private static boolean issuedByAnchor(final X509Certificate cert, final TrustAnchors anchors) {
        return anchors.anchors().stream().map(TrustAnchor::getTrustedCert).filter(Objects::nonNull)
                .anyMatch(a -> a.getSubjectX500Principal().equals(cert.getIssuerX500Principal()));
    }

    private static boolean isSelfSigned(final X509Certificate cert) {
        return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())
                && verifies(cert, cert.getPublicKey());
    }

    private static boolean verifies(final X509Certificate cert, final PublicKey key) {
        try {
            cert.verify(key);
            return true;
        } catch (final GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    /** The issuer key rule, shared with anchor loading: EC P-256/P-384/P-521 or RSA &ge; 2048. */
    static boolean allowedKey(final PublicKey key) {
        if (key instanceof RSAPublicKey rsa) {
            return rsa.getModulus().bitLength() >= MIN_RSA_BITS;
        }
        return key instanceof ECPublicKey ec && ALLOWED_CURVES.stream().anyMatch(c -> sameCurve(c, ec.getParams()));
    }

    private static void checkKey(final PublicKey key) {
        if (allowedKey(key)) {
            return;
        }
        throw new WalletVerificationException(WalletErrorCode.ALGORITHM_NOT_ALLOWED,
                "certificate key type or size not allowed");
    }

    private static boolean sameCurve(final ECParameterSpec a, final ECParameterSpec b) {
        return b != null && a.getCurve().equals(b.getCurve()) && a.getOrder().equals(b.getOrder())
                && a.getGenerator().equals(b.getGenerator()) && a.getCofactor() == b.getCofactor();
    }

    private static ECParameterSpec curve(final String name) {
        try {
            final AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(name));
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("EC curve " + name + " is not available", e);
        }
    }

    /** True when every CRL / OCSP URL in the path may be fetched under the outbound guard. */
    private boolean revocationEndpointsAllowed(final List<X509Certificate> path) {
        for (final X509Certificate cert : path) {
            for (final String url : revocationUrls(cert)) {
                if (!guard.isAllowed(url)) {
                    return false;
                }
            }
        }
        return true;
    }

    /** The CRL distribution point and OCSP AIA URIs of {@code cert}; an unparsable extension counts as blocked. */
    static List<String> revocationUrls(final X509Certificate cert) {
        final List<String> urls = new ArrayList<>();
        try {
            final byte[] crlDp = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
            if (crlDp != null) {
                for (final DistributionPoint dp : CRLDistPoint.getInstance(unwrap(crlDp)).getDistributionPoints()) {
                    final DistributionPointName name = dp.getDistributionPoint();
                    if (name != null && name.getType() == DistributionPointName.FULL_NAME) {
                        addUris(GeneralNames.getInstance(name.getName()).getNames(), urls);
                    } else if (name != null) {
                        urls.add("relative-name:"); // never fetchable by policy
                    }
                }
            }
            final byte[] aia = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
            if (aia != null) {
                for (final AccessDescription ad : AuthorityInformationAccess.getInstance(unwrap(aia))
                        .getAccessDescriptions()) {
                    if (AccessDescription.id_ad_ocsp.equals(ad.getAccessMethod())) {
                        addUris(new GeneralName[] {ad.getAccessLocation()}, urls);
                    }
                }
            }
        } catch (final RuntimeException e) {
            urls.add("malformed:"); // an extension we cannot read is not one we let the JDK fetch from
        }
        return urls;
    }

    private static void addUris(final GeneralName[] names, final List<String> out) {
        for (final GeneralName name : names) {
            if (name.getTagNo() == GeneralName.uniformResourceIdentifier) {
                out.add(name.getName().toString());
            } else {
                out.add("non-uri:"); // directoryName etc.: the JDK may resolve these via LDAP cert stores
            }
        }
    }

    private static ASN1Primitive unwrap(final byte[] extensionValue) {
        try {
            return ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(extensionValue).getOctets());
        } catch (final java.io.IOException e) {
            throw new IllegalArgumentException("malformed extension");
        }
    }

    /**
     * The SOFT_FAIL warning: the certificate's serial and subject DN (an issuer organisation or CA, never a holder)
     * only; never URLs, exception text or PID data.
     */
    private static void warn(final String what, final X509Certificate cert) {
        LOG.warn("Issuer certificate {}; accepted under SOFT_FAIL: serial={} subject={}", what,
                cert.getSerialNumber().toString(16), LogSafe.sanitize(cert.getSubjectX500Principal().getName()));
    }

    private static WalletVerificationException untrusted(final String detail) {
        return new WalletVerificationException(WalletErrorCode.ISSUER_UNTRUSTED, detail);
    }
}
