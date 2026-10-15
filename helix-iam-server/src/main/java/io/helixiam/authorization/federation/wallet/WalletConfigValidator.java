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
import io.helixiam.authorization.federation.ProviderSecretKeys;
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
 * map); {@link #validateStored} does the same for a raw stored map, so malformed values (bad JSON list, unknown enum,
 * bad number or boolean) are field errors too and nothing is thrown; {@link #requireValid} throws with all of them.
 * Messages never echo PEM content or key material, and an exception without a message gets a fixed one.
 *
 * <h2>Access certificate chain</h2>
 * With {@code accessKeyRef}, the key's own chain ({@link SigningKeyHandle#certificateChain()}) is the single source of
 * the request object's {@code x5c}; a configured {@code accessCertificateChain} must equal it. With the dev-only
 * {@code accessCertificatePrivateKey}, the configured chain is required. The effective chain must be leaf first, each
 * certificate issued by the next, without the root; its leaf must be currently valid and not self-signed (judged by
 * its signature verifying with its own key). These checks reuse Task 5's import checks
 * ({@link SoftwareRealmSigningKeys#checkLeafValidity}, {@link SoftwareRealmSigningKeys#verifiesWithOwnKey},
 * {@link SoftwareRealmSigningKeys#checkLeafFirstOrder}, {@link SoftwareRealmSigningKeys#isSelfSigned}).
 *
 * <h2>Other rules</h2>
 * alias present; the spec name {@code accessCertificateKeyRef} refused as renamed; for {@code x509_san_dns} the leaf
 * has {@code clientIdHost} as a DNS subjectAltName; exactly one signing key, which must belong to the leaf (the
 * {@code accessKeyRef} key, resolved in the realm, signs a probe that verifies with the leaf's public key; the dev PEM
 * is matched to it); a key that cannot be resolved or used is a field error; {@code registrationCertificate} parses
 * when set; at least one acceptable trust anchor; at least one known, non-repeated, non-empty credential format;
 * known, non-repeated, non-empty PID claims that {@link DcqlQueryBuilder} can request for the configured formats;
 * {@code direct_post} only in dev; TTL 60–900 s; clock skew 0–60 s; positive limits; status cache 0–900 s and bare
 * host names; {@code ATTRIBUTE_TUPLE} only with {@code acknowledgeWeakSubject}; {@code NONE} and
 * {@code customCredentialQueries} not supported yet; {@code minimumLoa} on the eIDAS ladder ({@link EidScheme#EUDI_WALLET}
 * delegates to it).
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

    private static final String CHAIN = "accessCertificateChain";
    /** The secret keys are the same under every wallet protocol alias. */
    private static final String SECRET_PROTOCOL = "eudi-wallet";
    private static final String KEY_REF = "accessKeyRef";
    private static final String DEV_KEY = "accessCertificatePrivateKey";

    private final RealmSigningKeys keys;
    private final DeploymentProfile profile;

    public WalletConfigValidator(final RealmSigningKeys keys, final DeploymentProfile profile) {
        this.keys = keys;
        this.profile = profile;
    }

    /**
     * Field → message for a raw stored map (the admin console's form): malformed values first, then every rule of
     * {@link #validate} on the config with those values defaulted. Never throws for bad input, so an admin write can
     * answer {@code 400 {message, fieldErrors}} instead of reaching {@code /error}.
     *
     * <p>Chosen over catching {@link WalletConfigFormatException} because the console needs format and rule problems
     * in one response; {@link WalletProviderConfig#fromStored} still throws (typed, with the same field map) for
     * runtime callers that must not build a provider from a malformed record.
     */
    public Map<String, String> validateStored(final String realmId, final String alias, final String displayName,
                                              final Map<String, String> stored) {
        final WalletProviderConfig.Parsed parsed = WalletProviderConfig.parseStored(alias, displayName, stored);
        final Map<String, String> errors = new LinkedHashMap<>(parsed.fieldErrors());
        validate(realmId, parsed.config()).forEach(errors::putIfAbsent);
        return errors;
    }

    /**
     * Field → message for an admin or import write of a wallet connection, judged as it will be stored: the write's
     * settings without control flags, plus each stored secret the write leaves out and does not clear (secrets are
     * write-only, so an update normally omits them). Shared by the admin API and realm import so both refuse the
     * same configs with the same messages ({@link #asAdminFields} names the fields as the admin API does).
     *
     * @param stored the stored connection's settings (with secrets), or an empty map / null for a new one
     */
    public Map<String, String> validateWrite(final String realmId, final String alias, final String displayName,
                                             final Map<String, String> write, final Map<String, String> stored) {
        final Map<String, String> effective = new LinkedHashMap<>();
        if (write != null) {
            write.forEach((k, v) -> {
                if (k != null && !ProviderSecretKeys.isControlKey(k)) {
                    effective.put(k, v);
                }
            });
        }
        if (stored != null) {
            for (final String key : ProviderSecretKeys.keysFor(SECRET_PROTOCOL)) {
                final String given = effective.get(key);
                if ((given == null || given.isBlank()) && !ProviderSecretKeys.clears(write, key)
                        && stored.get(key) != null && !stored.get(key).isBlank()) {
                    effective.put(key, stored.get(key));
                }
            }
        }
        final Map<String, String> errors = validateStored(realmId, alias, displayName, effective);
        if (!errors.containsKey("trustAnchors") && !errors.containsKey("dcql.trustedAuthorities")) {
            trustedAuthoritiesProblem(effective).ifPresent(p -> errors.put("dcql.trustedAuthorities", p));
        }
        return errors;
    }

    /**
     * Security review: a write that sets {@code dcql.trustedAuthorities} On explicitly must be able to name every
     * anchor's key identifier, which is never guessed ({@link TrustAnchors#authorityKeyIdentifiers}). Checked at save
     * time only: a provider loaded at runtime with such anchors is still built, and leaves trusted_authorities out with
     * a WARN ({@code WalletIdentityProvider}). The anchor's subject DN in the message is public certificate data.
     */
    private static java.util.Optional<String> trustedAuthoritiesProblem(final Map<String, String> stored) {
        final WalletProviderConfig.Parsed parsed = WalletProviderConfig.parseStored(null, null, stored);
        if (!Boolean.TRUE.equals(parsed.config().trustedAuthorities())) {
            return java.util.Optional.empty();
        }
        final List<java.security.cert.X509Certificate> missing;
        try {
            missing = TrustAnchors.fromPem(parsed.config().trustAnchors(), null, parsed.config().revocationChecking())
                    .withoutSubjectKeyIdentifier();
        } catch (final IllegalArgumentException e) {
            return java.util.Optional.empty(); // reported on trustAnchors
        }
        return missing.isEmpty() ? java.util.Optional.empty() : java.util.Optional.of("Trust anchor '"
                + missing.get(0).getSubjectX500Principal().getName() + "' has no SubjectKeyIdentifier, so "
                + "trusted_authorities cannot name it: use an anchor with that extension, or set this to Off or Default");
    }

    /** The admin API's field names: {@code alias} and {@code displayName} as is, settings as {@code config.<field>}. */
    public static Map<String, String> asAdminFields(final Map<String, String> fieldErrors) {
        final Map<String, String> out = new LinkedHashMap<>();
        fieldErrors.forEach((field, message) ->
                out.put("alias".equals(field) || "displayName".equals(field) ? field : "config." + field, message));
        return out;
    }

    /** Field → message for every problem (empty when the config is usable in {@code realmId}). */
    public Map<String, String> validate(final String realmId, final WalletProviderConfig c) {
        return validate(realmId, c, null);
    }

    /**
     * As {@link #validate(String, WalletProviderConfig)}, judging the given signing key instead of resolving
     * {@code accessKeyRef} again: the provider factory resolves the key once and validates the very handle that will
     * sign (so under {@code x509_san_dns} the leaf whose SAN was checked is the leaf that signs). For the dev PEM path
     * the handle must be the one built from the configured chain and key. A null {@code signingKey} resolves as usual.
     */
    public Map<String, String> validate(final String realmId, final WalletProviderConfig c,
                                        final SigningKeyHandle signingKey) {
        final Errors e = new Errors();
        if (c.alias() == null || c.alias().isBlank()) {
            e.add("alias", "alias is required");
        }
        if (c.accessCertificateKeyRef() != null && !c.accessCertificateKeyRef().isBlank()) {
            e.add("accessCertificateKeyRef", "accessCertificateKeyRef was renamed to accessKeyRef");
        }
        checkAccessKeyAndChain(realmId, c, signingKey, e);
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
            e.add("trustAnchors", message(ex, "The trust anchors are not acceptable")); // field-safe by contract
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
        requireValid(realmId, c, null);
    }

    /**
     * As {@link #requireValid(String, WalletProviderConfig)} for the given signing key (see
     * {@link #validate(String, WalletProviderConfig, SigningKeyHandle)}).
     */
    public void requireValid(final String realmId, final WalletProviderConfig c, final SigningKeyHandle signingKey) {
        final Map<String, String> errors = validate(realmId, c, signingKey);
        if (!errors.isEmpty()) {
            final StringBuilder sb = new StringBuilder("Wallet provider '").append(c.alias()).append("' is invalid: ");
            errors.forEach((field, message) -> sb.append(field).append(": ").append(message).append("; "));
            throw new IllegalArgumentException(sb.substring(0, sb.length() - 2));
        }
    }

    // ------------------------------------------------------------------------------------------------ key and chain

    private void checkAccessKeyAndChain(final String realmId, final WalletProviderConfig c,
                                        final SigningKeyHandle given, final Errors e) {
        final List<X509Certificate> configured = configuredChain(c, e);
        final boolean hasRef = c.accessKeyRef() != null && !c.accessKeyRef().isBlank();
        final boolean hasPem = c.accessCertificatePrivateKey() != null && !c.accessCertificatePrivateKey().isBlank();
        List<X509Certificate> effective = configured;
        String chainField = CHAIN;
        if (hasPem && !profile.isDev()) {
            e.add(DEV_KEY, "A raw private key is accepted only in the dev profile; import it and set accessKeyRef");
        } else if (hasRef && hasPem) {
            e.add(DEV_KEY, "Set either accessKeyRef or accessCertificatePrivateKey, not both");
        } else if (!hasRef && !hasPem) {
            e.add(KEY_REF, "accessKeyRef is required (a signing key imported into this realm)");
        } else if (hasPem) {
            if (c.accessCertificateChain() == null) {
                e.add(CHAIN, "accessCertificateChain (PEM, leaf first) is required with accessCertificatePrivateKey");
            } else if (configured != null) {
                checkDevKey(c.accessCertificatePrivateKey(), configured.get(0), e);
                if (given != null && (!configured.equals(given.certificateChain())
                        || !signsFor(given, configured.get(0)))) {
                    e.add(DEV_KEY, "The signing key is not the configured accessCertificatePrivateKey and chain");
                }
            }
        } else {
            final SigningKeyHandle handle = given != null ? given : resolve(realmId, c.accessKeyRef(), e);
            if (handle != null) {
                final List<X509Certificate> keyChain = handle.certificateChain();
                if (keyChain == null || keyChain.isEmpty()) {
                    e.add(KEY_REF, "The key behind accessKeyRef has no certificate chain");
                    return;
                }
                if (c.accessCertificateChain() != null && configured != null && !configured.equals(keyChain)) {
                    e.add(CHAIN, "accessCertificateChain must equal the certificate chain of the key behind accessKeyRef");
                }
                if (!signsFor(handle, keyChain.get(0))) {
                    e.add(KEY_REF, "The key behind accessKeyRef does not match the access certificate");
                }
                effective = keyChain;
                chainField = c.accessCertificateChain() == null ? KEY_REF : CHAIN;
            }
        }
        if (effective != null) {
            checkChain(effective, chainField, e);
            if (c.clientIdScheme() == WalletProviderConfig.ClientIdScheme.X509_SAN_DNS) {
                checkSan(c, effective.get(0), e);
            }
        }
    }

    /** The configured chain, parsed; null when absent or unparseable (then reported). */
    private static List<X509Certificate> configuredChain(final WalletProviderConfig c, final Errors e) {
        if (c.accessCertificateChain() == null) {
            return null;
        }
        try {
            return SoftwareRealmSigningKeys.parseCertificateChain(c.accessCertificateChain());
        } catch (final IllegalArgumentException ex) {
            e.add(CHAIN, "accessCertificateChain could not be parsed as PEM certificates");
            return null;
        }
    }

    /** Task 5's import rules on the chain that goes into x5c. */
    private static void checkChain(final List<X509Certificate> chain, final String field, final Errors e) {
        final X509Certificate leaf = chain.get(0);
        try {
            SoftwareRealmSigningKeys.checkLeafValidity(leaf);
        } catch (final IllegalArgumentException ex) {
            e.add(field, message(ex, "The access certificate is not currently valid"));
        }
        if (SoftwareRealmSigningKeys.verifiesWithOwnKey(leaf)) {
            e.add(field, "The access certificate must not be self-signed (HAIP)");
            return;
        }
        try {
            SoftwareRealmSigningKeys.checkLeafFirstOrder(chain);
        } catch (final IllegalArgumentException ex) {
            e.add(field, message(ex, "The certificate chain must be ordered leaf first"));
        }
        if (chain.size() > 1 && SoftwareRealmSigningKeys.isSelfSigned(chain.get(chain.size() - 1))) {
            e.add(field, "The certificate chain must not include the root (self-signed) certificate; "
                    + "x5c never carries it");
        }
    }

    private static void checkSan(final WalletProviderConfig c, final X509Certificate leaf, final Errors e) {
        if (c.clientIdHost() == null || c.clientIdHost().isBlank()) {
            e.add("clientIdHost", "clientIdHost is required for x509_san_dns");
            return;
        }
        final String host = c.clientIdHost().trim();
        if (dnsNames(leaf).stream().noneMatch(host::equalsIgnoreCase)) {
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

    private static void checkDevKey(final String pem, final X509Certificate leaf, final Errors e) {
        try {
            if (!SoftwareRealmSigningKeys.privateKeyMatches(pem, leaf.getPublicKey())) {
                e.add(DEV_KEY, "accessCertificatePrivateKey does not match the access certificate");
            }
        } catch (final IllegalArgumentException ex) {
            e.add(DEV_KEY, message(ex, "accessCertificatePrivateKey could not be read")); // field-safe, never the PEM
        }
    }

    /** The realm's key, or null with a field error: a missing / foreign / unsupported ref, or a key that is unusable. */
    private SigningKeyHandle resolve(final String realmId, final String keyRef, final Errors e) {
        try {
            return keys.resolve(realmId, keyRef);
        } catch (final NoSuchElementException | IllegalArgumentException | UnsupportedOperationException ex) {
            e.add(KEY_REF, message(ex, "accessKeyRef could not be resolved"));
        } catch (final RuntimeException ex) { // corrupt or undecryptable stored key (IllegalStateException, ...)
            e.add(KEY_REF, "The key behind accessKeyRef cannot be used");
        }
        return null;
    }

    /** The key proves itself: a probe it signs verifies with the leaf's public key. */
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

    private static String message(final RuntimeException ex, final String fallback) {
        return ex.getMessage() == null || ex.getMessage().isBlank() ? fallback : ex.getMessage();
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
            if (format == null || format.isBlank()) {
                e.add("credentialFormats", "credentialFormats must not contain empty entries");
                return false;
            }
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
            if (claim == null || claim.isBlank()) {
                e.add("pid.requestedClaims", "pid.requestedClaims must not contain empty entries");
                claimsOk = false;
                break;
            }
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
                e.add("pid.requestedClaims", "The PID claims cannot be requested in these formats: "
                        + message(ex, "refused by the query builder"));
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
