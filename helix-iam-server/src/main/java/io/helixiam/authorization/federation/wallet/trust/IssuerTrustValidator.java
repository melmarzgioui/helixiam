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

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
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
 * <p><b>Revocation</b> runs only after the PKIX pass (no revocation) has proven the chain reaches an anchor at
 * {@code at}, so nothing is fetched for a forged chain. Every certificate below the anchor (the leaf and each
 * intermediate) is then checked <em>on its own</em> by {@link IssuerRevocationClient}, against its own issuer: OCSP
 * first, then the CRL distribution points, fetched by HelixIAM (outbound guard, pinned connection, no redirects, size
 * caps, deadline, cache) and validated by the JDK PKIX revocation checker. Then, per {@link RevocationMode}:
 * <ul>
 *   <li>{@code OFF}: no revocation check and no network access.</li>
 *   <li>any certificate {@code REVOKED}: "certificate revoked", in both other modes, whatever the other
 *       certificates' status (an undeterminable CA never hides a revoked leaf or lower CA).</li>
 *   <li>{@code HARD_FAIL} (the default): a certificate whose status cannot be determined (no responder or distribution
 *       point, unreachable, timed out, too large, or an answer that does not verify) is refused with
 *       "certificate revocation status unavailable", or "revocation endpoint not allowed" when every source it names
 *       was refused by policy (a non-http(s) scheme such as {@code ldap:}, a non-URI name, or a host on a loopback /
 *       private / link-local address).</li>
 *   <li>{@code SOFT_FAIL}: such a certificate is accepted, with a warning carrying only its serial and subject DN;
 *       the other certificates are still checked.</li>
 * </ul>
 *
 * <p><b>SSRF (security concern).</b> The CRL distribution point and OCSP AIA URLs come from the presented,
 * attacker-supplied certificates. Mitigations: (1) nothing is fetched unless the chain already validates to a
 * configured anchor, so only certificates a trusted CA issued can steer a fetch; (2) every URL passes
 * {@link io.helixiam.common.net.OutboundUrlGuard} (http/https only; loopback, private, link-local and metadata
 * addresses refused) and is fetched over a connection to the very address the guard validated (no DNS rebinding),
 * without following redirects, within 3 s connect / 5 s total per fetch and 10 s per chain, capped at 64 KB (OCSP) and
 * {@code helix.wallet.revocation.max-crl-bytes} (CRL, default 10 MB). The JDK's own revocation fetching is never used.
 */
public final class IssuerTrustValidator {

    private static final Logger LOG = LogManager.getLogger(IssuerTrustValidator.class);

    /** The longest {@code x5c} / {@code x5chain} accepted (after pinned intermediates are added). */
    static final int MAX_CHAIN_LENGTH = 10;
    private static final int MIN_RSA_BITS = 2048;
    private static final List<ECParameterSpec> ALLOWED_CURVES =
            List.of(curve("secp256r1"), curve("secp384r1"), curve("secp521r1"));

    private final IssuerRevocationClient revocation;

    /** Production default: revocation URLs pass the environment-configured (block-private) outbound guard. */
    public IssuerTrustValidator() {
        this(new OutboundUrlGuard());
    }

    /** A validator with its own revocation client (default settings, own cache). */
    public IssuerTrustValidator(final OutboundUrlGuard guard) {
        this(new IssuerRevocationClient(Objects.requireNonNull(guard, "guard"),
                IssuerRevocationClient.Settings.DEFAULTS, java.time.Clock.systemUTC()));
    }

    /** A validator on a shared revocation client (one cache and one byte budget for every wallet provider). */
    public IssuerTrustValidator(final IssuerRevocationClient revocation) {
        this.revocation = Objects.requireNonNull(revocation, "revocation");
    }

    /** Validates leaf-first chain (as in x5c / x5chain) to a configured anchor at {@code at}; returns the leaf. */
    public X509Certificate validate(final List<X509Certificate> chain, final TrustAnchors anchors, final Instant at) {
        return validateChain(chain, anchors, at).leaf();
    }

    /**
     * As {@link #validate}, returning what PKIX proved: the validated path (the presented chain with trailing anchor
     * certificates removed and pinned intermediates added, leaf first) and the {@link TrustAnchor} it chains to. Rules
     * about <em>who</em> issued a certificate must use this, never the presented chain, which may carry extra
     * certificates (for example another issuer's anchor appended at the end).
     */
    public ValidatedChain validateChain(final List<X509Certificate> chain, final TrustAnchors anchors,
            final Instant at) {
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
        final TrustAnchor anchor = validatePath(path, anchors, at, leaf);
        return new ValidatedChain(path, anchor);
    }

    /** Returns the anchor PKIX validated the path to. */
    private TrustAnchor validatePath(final List<X509Certificate> path, final TrustAnchors anchors, final Instant at,
            final X509Certificate leaf) {
        final CertPath certPath;
        final CertPathValidator validator;
        try {
            certPath = CertificateFactory.getInstance("X.509").generateCertPath(path);
            validator = CertPathValidator.getInstance("PKIX");
        } catch (final GeneralSecurityException e) {
            throw untrusted("certificate chain not trusted");
        }
        // The full path check without revocation. No network access happens before the chain is proven to reach a
        // configured anchor, so a forged chain can never make the server fetch its CRL / OCSP URLs.
        final TrustAnchor anchor;
        try {
            anchor = ((PKIXCertPathValidatorResult) validator.validate(certPath, parameters(anchors, at)))
                    .getTrustAnchor();
        } catch (final CertPathValidatorException e) {
            throw mapFailure(e);
        } catch (final GeneralSecurityException e) {
            throw untrusted("certificate chain not trusted");
        }
        final RevocationMode mode = anchors.revocation(); // never null: TrustAnchors defaults it to HARD_FAIL
        if (mode != RevocationMode.OFF) {
            checkRevocation(path, anchor, at, mode);
        }
        return anchor;
    }

    /**
     * Every certificate below the anchor on its own, against its own issuer (the next certificate, or the anchor for
     * the top one). A revoked certificate anywhere refuses; an undeterminable one refuses under HARD_FAIL and is
     * logged under SOFT_FAIL.
     */
    private void checkRevocation(final List<X509Certificate> path, final TrustAnchor anchor, final Instant at,
            final RevocationMode mode) {
        final long deadline = System.nanoTime() + IssuerRevocationClient.CHAIN_BUDGET.toNanos();
        final List<IssuerRevocationClient.Outcome> outcomes = new ArrayList<>(path.size());
        for (int i = 0; i < path.size(); i++) {
            final TrustAnchor issuer = i + 1 < path.size() ? new TrustAnchor(path.get(i + 1), null) : anchor;
            outcomes.add(revocation.status(path.get(i), issuer, at, deadline));
        }
        if (outcomes.contains(IssuerRevocationClient.Outcome.REVOKED)) {
            throw untrusted("certificate revoked");
        }
        for (int i = 0; i < path.size(); i++) {
            final IssuerRevocationClient.Outcome outcome = outcomes.get(i);
            if (outcome == IssuerRevocationClient.Outcome.GOOD) {
                continue;
            }
            final boolean blocked = outcome == IssuerRevocationClient.Outcome.BLOCKED;
            if (mode == RevocationMode.HARD_FAIL) {
                throw untrusted(blocked ? "revocation endpoint not allowed"
                        : "certificate revocation status unavailable");
            }
            warn(blocked ? "revocation endpoint not allowed" : "revocation status unavailable", path.get(i));
        }
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
