/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import io.helixiam.authorization.federation.eid.EidLevelOfAssurance;
import io.helixiam.authorization.federation.eid.EidScheme;
import io.helixiam.authorization.federation.wallet.dcql.DcqlQueryBuilder;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;
import io.helixiam.authorization.service.key.RealmSigningKeys;
import io.helixiam.authorization.service.key.SigningKeyHandle;
import io.helixiam.authorization.service.key.SoftwareRealmSigningKeys;
import io.helixiam.common.startup.DeploymentProfile;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Checks a {@link WalletProviderConfig} before it is used (spec §9: at startup and on store refresh, fail fast).
 * {@link #validate} returns field → message (the admin API's {@code fieldErrors} shape, field names as in the stored
 * map); {@link #requireValid} throws with all of them. Messages never echo PEM content or key material.
 *
 * <p>Rules: alias present; access certificate parses and is not self-signed (judged by its signature verifying with its
 * own key, {@link SoftwareRealmSigningKeys#verifiesWithOwnKey}); for {@code x509_san_dns} the leaf has
 * {@code clientIdHost} as a DNS subjectAltName; exactly one signing key: {@code accessKeyRef} (resolved in the realm,
 * and proven to sign for the certificate's public key) or, in the dev profile only, {@code accessCertificatePrivateKey}
 * (proven to match the certificate); {@code registrationCertificate} parses when set; at least one acceptable trust
 * anchor; at least one known, non-repeated credential format; known, non-repeated PID claims that
 * {@link DcqlQueryBuilder} can request for the configured formats; {@code direct_post} only in dev; TTL 60–900 s;
 * clock skew 0–60 s; positive limits; status cache 0–900 s and bare host names; {@code ATTRIBUTE_TUPLE} only with
 * {@code acknowledgeWeakSubject}; {@code NONE} and {@code customCredentialQueries} not supported yet; {@code minimumLoa}
 * on the eIDAS ladder ({@link EidScheme#EUDI_WALLET} delegates to it).
 */
@Component
public class WalletConfigValidator {

    private static final Pattern URI_SCHEME = Pattern.compile("[A-Za-z][A-Za-z0-9+.-]*");
    private static final Set<String> FORBIDDEN_SCHEMES = Set.of("javascript", "data", "vbscript", "file", "blob",
            "about");
    private static final Pattern HOST_NAME = Pattern.compile(
            "(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*");
    private static final Set<String> FORMATS = Set.of(DcqlQueryBuilder.SD_JWT_FORMAT, DcqlQueryBuilder.MDOC_FORMAT);
    private static final byte[] KEY_PROBE = "helix-wallet-access-key-check".getBytes(StandardCharsets.US_ASCII);
    private static final int DNS_NAME = 2;
    private static final int MIN_TTL = 60;
    private static final int MAX_TTL = 900;
    private static final int MAX_CLOCK_SKEW = 60;
    private static final int MAX_STATUS_CACHE = 900;

    private final RealmSigningKeys keys;
    private final DeploymentProfile profile;

    public WalletConfigValidator(final RealmSigningKeys keys, final DeploymentProfile profile) {
        this.keys = keys;
        this.profile = profile;
    }

    /** Field → message for every problem (empty when the config is usable in {@code realmId}). */
    public Map<String, String> validate(final String realmId, final WalletProviderConfig c) {
        final Errors e = new Errors();
        if (c.alias() == null || c.alias().isBlank()) {
            e.add("alias", "alias is required");
        }
        final X509Certificate leaf = accessCertificate(c, e);
        if (leaf != null && c.clientIdScheme() == WalletProviderConfig.ClientIdScheme.X509_SAN_DNS) {
            checkSan(c, leaf, e);
        }
        checkKey(realmId, c, leaf, e);
        if (c.registrationCertificate() != null) {
            try {
                SoftwareRealmSigningKeys.parseCertificateChain(c.registrationCertificate());
            } catch (final IllegalArgumentException ex) {
                e.add("registrationCertificate", "registrationCertificate could not be parsed as PEM certificates");
            }
        }
        checkInvocationScheme(c.invocationScheme(), e);
        if (c.responseMode() == WalletProviderConfig.ResponseMode.DIRECT_POST && !profile.isDev()) {
            e.add("responseMode", "responseMode direct_post (unencrypted) is allowed only in the dev profile");
        }
        range(e, "transactionTtlSeconds", c.transactionTtlSeconds(), MIN_TTL, MAX_TTL);
        range(e, "clockSkewSeconds", c.clockSkewSeconds(), 0, MAX_CLOCK_SKEW);
        final boolean formatsOk = checkFormats(c.credentialFormats(), e);
        checkPid(c, formatsOk, e);
        if (!c.customCredentialQueries().isEmpty()) {
            e.add("customCredentialQueries", "customCredentialQueries are not supported yet");
        }
        try {
            TrustAnchors.fromPem(c.trustAnchors(), null, c.revocationChecking());
        } catch (final IllegalArgumentException ex) {
            e.add("trustAnchors", ex.getMessage()); // field-safe by contract (TrustAnchors.fromPem)
        }
        checkStatusList(c.statusList(), e);
        checkSubject(c.subject(), e);
        if (EidLevelOfAssurance.rung(EidScheme.EUDI_WALLET, c.minimumLoa()) == 0) {
            e.add("minimumLoa",
                    "minimumLoa must be an eIDAS level of assurance (http://eidas.europa.eu/LoA/low|substantial|high)");
        }
        positive(e, "limits.maxJwtBytes", c.limits().maxJwtBytes());
        positive(e, "limits.cborMaxDepth", c.limits().cborMaxDepth());
        positive(e, "limits.cborMaxItems", c.limits().cborMaxItems());
        positive(e, "limits.cborMaxBytes", c.limits().cborMaxBytes());
        return e.fields;
    }

    /** @throws IllegalArgumentException naming the alias and every {@code field: message} when the config is invalid */
    public void requireValid(final String realmId, final WalletProviderConfig c) {
        final Map<String, String> errors = validate(realmId, c);
        if (!errors.isEmpty()) {
            final StringBuilder sb = new StringBuilder("Wallet provider '").append(c.alias()).append("' is invalid: ");
            errors.forEach((field, message) -> sb.append(field).append(": ").append(message).append("; "));
            throw new IllegalArgumentException(sb.substring(0, sb.length() - 2));
        }
    }

    // ------------------------------------------------------------------------------------------------ certificate

    private static X509Certificate accessCertificate(final WalletProviderConfig c, final Errors e) {
        if (c.accessCertificateChain() == null) {
            e.add("accessCertificateChain", "accessCertificateChain (PEM, leaf first) is required");
            return null;
        }
        final List<X509Certificate> chain;
        try {
            chain = SoftwareRealmSigningKeys.parseCertificateChain(c.accessCertificateChain());
        } catch (final IllegalArgumentException ex) {
            e.add("accessCertificateChain", "accessCertificateChain could not be parsed as PEM certificates");
            return null;
        }
        final X509Certificate leaf = chain.get(0);
        if (SoftwareRealmSigningKeys.verifiesWithOwnKey(leaf)) {
            e.add("accessCertificateChain", "The access certificate must not be self-signed (HAIP)");
        }
        return leaf;
    }

    private static void checkSan(final WalletProviderConfig c, final X509Certificate leaf, final Errors e) {
        if (c.clientIdHost() == null || c.clientIdHost().isBlank()) {
            e.add("clientIdHost", "clientIdHost is required for x509_san_dns");
            return;
        }
        final String host = c.clientIdHost().trim();
        if (!dnsNames(leaf).stream().anyMatch(host::equalsIgnoreCase)) {
            e.add("clientIdHost", "clientIdHost must be a DNS subjectAltName of the access certificate (x509_san_dns)");
        }
    }

    private static Set<String> dnsNames(final X509Certificate leaf) {
        final Set<String> names = new HashSet<>();
        try {
            final Collection<List<?>> sans = leaf.getSubjectAlternativeNames();
            if (sans != null) {
                for (final List<?> san : sans) {
                    if (san.size() >= 2 && Integer.valueOf(DNS_NAME).equals(san.get(0))
                            && san.get(1) instanceof String name) {
                        names.add(name);
                    }
                }
            }
        } catch (final CertificateParsingException ex) {
            return Set.of();
        }
        return names;
    }

    // ------------------------------------------------------------------------------------------------ signing key

    private void checkKey(final String realmId, final WalletProviderConfig c, final X509Certificate leaf,
                          final Errors e) {
        final boolean hasRef = c.accessKeyRef() != null && !c.accessKeyRef().isBlank();
        final boolean hasPem = c.accessCertificatePrivateKey() != null && !c.accessCertificatePrivateKey().isBlank();
        if (hasPem && !profile.isDev()) {
            e.add("accessCertificatePrivateKey",
                    "A raw private key is accepted only in the dev profile; import it and set accessKeyRef");
            return;
        }
        if (hasRef && hasPem) {
            e.add("accessCertificatePrivateKey", "Set either accessKeyRef or accessCertificatePrivateKey, not both");
            return;
        }
        if (!hasRef && !hasPem) {
            e.add("accessKeyRef", "accessKeyRef is required (a signing key imported into this realm)");
            return;
        }
        if (hasPem) {
            checkDevKey(c.accessCertificatePrivateKey(), leaf, e);
        } else {
            checkKeyRef(realmId, c.accessKeyRef(), leaf, e);
        }
    }

    private static void checkDevKey(final String pem, final X509Certificate leaf, final Errors e) {
        try {
            final boolean matches = SoftwareRealmSigningKeys.privateKeyMatches(pem, leaf == null ? null
                    : leaf.getPublicKey());
            if (leaf != null && !matches) {
                e.add("accessCertificatePrivateKey", "accessCertificatePrivateKey does not match the access certificate");
            }
        } catch (final IllegalArgumentException ex) {
            e.add("accessCertificatePrivateKey", ex.getMessage()); // field-safe by contract, never the PEM
        }
    }

    private void checkKeyRef(final String realmId, final String keyRef, final X509Certificate leaf, final Errors e) {
        final SigningKeyHandle handle;
        try {
            handle = keys.resolve(realmId, keyRef);
        } catch (final NoSuchElementException | IllegalArgumentException | UnsupportedOperationException ex) {
            e.add("accessKeyRef", ex.getMessage());
            return;
        }
        if (leaf != null && !signsFor(handle, leaf)) {
            e.add("accessKeyRef", "The key behind accessKeyRef does not match the access certificate");
        }
    }

    /** The key proves itself: a probe it signs verifies with the configured leaf's public key. */
    private static boolean signsFor(final SigningKeyHandle handle, final X509Certificate leaf) {
        if (!(leaf.getPublicKey() instanceof ECPublicKey publicKey)) {
            return false;
        }
        try {
            final JWSHeader header = new JWSHeader(handle.algorithm());
            final Base64URL signature = handle.signer().sign(header, KEY_PROBE);
            return new ECDSAVerifier(publicKey).verify(header, KEY_PROBE, signature);
        } catch (final JOSEException ex) {
            return false;
        }
    }

    // ------------------------------------------------------------------------------------------------ request

    private static void checkInvocationScheme(final String scheme, final Errors e) {
        if (!URI_SCHEME.matcher(scheme).matches()) {
            e.add("invocationScheme", "invocationScheme must be a URI scheme (e.g. haip-vp, openid4vp, eudi-openid4vp)");
        } else if (FORBIDDEN_SCHEMES.contains(scheme.toLowerCase(Locale.ROOT))) {
            e.add("invocationScheme", "invocationScheme '" + scheme.toLowerCase(Locale.ROOT) + "' is not allowed");
        }
    }

    private static boolean checkFormats(final List<String> formats, final Errors e) {
        if (formats.isEmpty()) {
            e.add("credentialFormats", "At least one credential format is required");
            return false;
        }
        final Set<String> seen = new HashSet<>();
        for (final String format : formats) {
            if (!FORMATS.contains(format)) {
                e.add("credentialFormats", "Unknown credential format: " + format + " (dc+sd-jwt or mso_mdoc)");
                return false;
            }
            if (!seen.add(format)) {
                e.add("credentialFormats", "Credential format listed twice: " + format);
                return false;
            }
        }
        return true;
    }

    private static void checkPid(final WalletProviderConfig c, final boolean formatsOk, final Errors e) {
        final WalletProviderConfig.Pid pid = c.pid();
        boolean claimsOk = true;
        if (pid.requestedClaims().isEmpty()) {
            e.add("pid.requestedClaims", "At least one PID claim is required");
            claimsOk = false;
        }
        final Set<String> seen = new HashSet<>();
        for (final String claim : pid.requestedClaims()) {
            if (!DcqlQueryBuilder.isPidClaim(claim)) {
                e.add("pid.requestedClaims", "Not a PID claim: " + claim);
                claimsOk = false;
                break;
            }
            if (!seen.add(claim)) {
                e.add("pid.requestedClaims", "PID claim requested twice: " + claim);
                claimsOk = false;
                break;
            }
        }
        if (c.credentialFormats().contains(DcqlQueryBuilder.SD_JWT_FORMAT) && (pid.sdJwtVcts().isEmpty()
                || pid.sdJwtVcts().stream().anyMatch(v -> v == null || v.isBlank()))) {
            e.add("pid.sdJwtVcts", "dc+sd-jwt needs at least one vct and no blank one");
            return;
        }
        if (formatsOk && claimsOk) {
            try { // the builder's remaining rules, e.g. an mdoc query left without any mdoc claim
                new DcqlQueryBuilder().pidQuery(pid.toQuerySpec(), c.credentialFormats());
            } catch (final IllegalArgumentException ex) {
                e.add("pid.requestedClaims", "The PID claims cannot be requested in these formats: " + ex.getMessage());
            }
        }
    }

    // ------------------------------------------------------------------------------------------------ policies

    private static void checkStatusList(final WalletProviderConfig.StatusList status, final Errors e) {
        range(e, "statusList.maxCacheSeconds", status.maxCacheSeconds(), 0, MAX_STATUS_CACHE);
        for (final String host : status.allowedHosts()) {
            if (host == null || !HOST_NAME.matcher(host).matches()) {
                e.add("statusList.allowedHosts", "statusList.allowedHosts must be host names (no scheme, port or path)");
                return;
            }
        }
    }

    private static void checkSubject(final WalletProviderConfig.Subject subject, final Errors e) {
        if (subject.strategy() == WalletProviderConfig.Subject.Strategy.NONE) {
            e.add("subject.strategy", "subject.strategy NONE (verify-only) is not supported yet");
        } else if (subject.strategy() == WalletProviderConfig.Subject.Strategy.ATTRIBUTE_TUPLE
                && !subject.acknowledgeWeakSubject()) {
            e.add("subject.strategy", "subject.strategy ATTRIBUTE_TUPLE requires subject.acknowledgeWeakSubject=true");
        }
    }

    private static void range(final Errors e, final String field, final int value, final int min, final int max) {
        if (value < min || value > max) {
            e.add(field, field + " must be between " + min + " and " + max);
        }
    }

    private static void positive(final Errors e, final String field, final int value) {
        if (value < 1) {
            e.add(field, field + " must be positive");
        }
    }

    /** First message per field wins. */
    private static final class Errors {
        private final Map<String, String> fields = new LinkedHashMap<>();

        void add(final String field, final String message) {
            fields.putIfAbsent(field, message);
        }
    }
}
