/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.helixiam.authorization.federation.ProviderSecretKeys;
import io.helixiam.authorization.federation.wallet.dcql.DcqlQueryBuilder;
import io.helixiam.authorization.federation.wallet.dcql.PidQuerySpec;
import io.helixiam.authorization.federation.wallet.mdoc.CborLimits;
import io.helixiam.authorization.federation.wallet.status.StatusPolicy;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/**
 * One EUDI Wallet (OpenID4VP verifier) identity provider, spec §9: static config ({@code helix.federation.wallet[*]},
 * bound by Spring) or stored config ({@link #fromStored}, the admin console's flat map). Null members get their
 * defaults, so a YAML entry or stored map only has to name what differs. {@link WalletConfigValidator} decides
 * whether a config is usable; this record only holds it.
 *
 * <h2>Differences from the spec §9 block (recorded rulings)</h2>
 * <ul>
 *   <li>{@code accessKeyRef} (a {@link io.helixiam.authorization.service.key.RealmSigningKeys} reference such as
 *       {@code software:<realm>/<name>}) replaces {@code accessCertificateKeyRef}. The spec name is still bound and
 *       stored so that the validator can refuse it ("renamed to accessKeyRef") instead of silently ignoring it.
 *       {@code accessCertificatePrivateKey} (a raw PEM) is accepted only in the dev profile and is a provider secret
 *       ({@link ProviderSecretKeys}): {@link #toStored} never emits it (only {@link #storedSecrets} does) and
 *       {@link #toString} never shows it.</li>
 *   <li>{@code accessCertificateChain} is optional with {@code accessKeyRef}: the key's own chain
 *       ({@code SigningKeyHandle.certificateChain()}) is the single source of the request object's {@code x5c}; a
 *       configured chain must equal it.</li>
 *   <li>{@code clientIdScheme} defaults to {@code x509_hash} (the scheme HAIP guarantees); {@code invocationScheme}
 *       defaults to {@code haip-vp}.</li>
 *   <li>{@code pid.sdJwtVcts} defaults to the base PID type plus the national type recorded in the spec notes (§7.1);
 *       {@code age_over_18} is not requested by default (no PID attribute since Rulebook v1.1).</li>
 *   <li>{@code statusList.required} defaults to {@code false}; {@code limits} (JWT and CBOR bounds) is added.</li>
 * </ul>
 *
 * <h2>Stored form</h2>
 * A flat {@code Map<String,String>}: nested members dotted ({@code pid.mdocDoctype}, {@code statusList.required},
 * {@code limits.maxJwtBytes}, ...), lists as JSON arrays of strings ({@code credentialFormats}, {@code pid.sdJwtVcts},
 * {@code pid.requestedClaims}, {@code statusList.allowedHosts}, {@code customCredentialQueries}), PEM bundles as plain
 * strings, enums case-insensitive by name or wire value ({@code x509_hash}, {@code direct_post.jwt}). An absent or
 * blank value means the default. Malformed values are collected per field: {@link #fromStored} throws them together as
 * a {@link WalletConfigFormatException}, {@link WalletConfigValidator#validateStored} returns them as field errors.
 *
 * <p>Lists keep null elements (YAML or programmatic construction) so that the validator reports them as field errors
 * instead of failing with a {@link NullPointerException} here.
 */
public record WalletProviderConfig(String alias, String displayName, ClientIdScheme clientIdScheme,
        String clientIdHost, String accessCertificateChain, String accessKeyRef, String accessCertificateKeyRef,
        String accessCertificatePrivateKey,
        String registrationCertificate, String invocationScheme, ResponseMode responseMode,
        RequestUriMethod requestUriMethod, Integer transactionTtlSeconds, List<String> credentialFormats, Pid pid,
        List<String> customCredentialQueries, String trustAnchors, TrustAnchors.RevocationMode revocationChecking,
        StatusList statusList, Subject subject, String minimumLoa, Integer clockSkewSeconds,
        boolean allowLegacyVcSdJwtTyp, Limits limits) {

    public static final String DEFAULT_INVOCATION_SCHEME = "haip-vp";
    public static final int DEFAULT_TRANSACTION_TTL_SECONDS = 300;
    public static final List<String> DEFAULT_FORMATS =
            List.of(DcqlQueryBuilder.SD_JWT_FORMAT, DcqlQueryBuilder.MDOC_FORMAT);
    public static final String DEFAULT_MINIMUM_LOA = "http://eidas.europa.eu/LoA/high";
    public static final int DEFAULT_CLOCK_SKEW_SECONDS = 60;

    private static final ObjectMapper JSON = new ObjectMapper();
    /** The protocol whose secret keys {@link #toStored} leaves out (the same set for every wallet alias). */
    private static final String SECRET_PROTOCOL = "eudi-wallet";

    public WalletProviderConfig {
        clientIdScheme = clientIdScheme == null ? ClientIdScheme.X509_HASH : clientIdScheme;
        invocationScheme = isBlank(invocationScheme) ? DEFAULT_INVOCATION_SCHEME : invocationScheme.trim();
        responseMode = responseMode == null ? ResponseMode.DIRECT_POST_JWT : responseMode;
        requestUriMethod = requestUriMethod == null ? RequestUriMethod.GET : requestUriMethod;
        transactionTtlSeconds = transactionTtlSeconds == null ? DEFAULT_TRANSACTION_TTL_SECONDS : transactionTtlSeconds;
        credentialFormats = credentialFormats == null ? DEFAULT_FORMATS : copy(credentialFormats);
        pid = pid == null ? new Pid(null, null, null) : pid;
        customCredentialQueries = customCredentialQueries == null ? List.of() : copy(customCredentialQueries);
        revocationChecking = revocationChecking == null ? TrustAnchors.RevocationMode.HARD_FAIL : revocationChecking;
        statusList = statusList == null ? new StatusList(false, null, null, null) : statusList;
        subject = subject == null ? new Subject(null, false) : subject;
        minimumLoa = isBlank(minimumLoa) ? DEFAULT_MINIMUM_LOA : minimumLoa.trim();
        clockSkewSeconds = clockSkewSeconds == null ? DEFAULT_CLOCK_SKEW_SECONDS : clockSkewSeconds;
        limits = limits == null ? new Limits(null, null, null, null) : limits;
    }

    /** {@code client_id} prefix (OpenID4VP §5.9.3). */
    public enum ClientIdScheme {
        X509_HASH("x509_hash"), X509_SAN_DNS("x509_san_dns");

        private final String value;

        ClientIdScheme(final String value) {
            this.value = value;
        }

        public String value() {
            return value;
        }
    }

    /** How the wallet returns the response; {@code direct_post} (unencrypted) is dev only. */
    public enum ResponseMode {
        DIRECT_POST_JWT("direct_post.jwt"), DIRECT_POST("direct_post");

        private final String value;

        ResponseMode(final String value) {
            this.value = value;
        }

        public String value() {
            return value;
        }
    }

    /** {@code request_uri_method}. */
    public enum RequestUriMethod {
        GET("get"), POST("post");

        private final String value;

        RequestUriMethod(final String value) {
            this.value = value;
        }

        public String value() {
            return value;
        }
    }

    /**
     * The PID request. {@link #toQuerySpec()} (what the request asks for) and {@link #acceptedVcts()} /
     * {@link #acceptedDoctype()} (what the verifier accepts) read the same members, so the DCQL {@code vct_values} and
     * the {@link VerificationContext} can never diverge.
     *
     * @param sdJwtVcts       accepted SD-JWT VC types (null: {@link #DEFAULT_SD_JWT_VCTS})
     * @param mdocDoctype     the mdoc doctype (null: {@link PidQuerySpec#DEFAULT_MDOC_DOCTYPE})
     * @param requestedClaims canonical (SD-JWT VC) claim names, see {@link DcqlQueryBuilder} (null:
     *                        {@link #DEFAULT_REQUESTED_CLAIMS})
     */
    public record Pid(List<String> sdJwtVcts, String mdocDoctype, List<String> requestedClaims) {

        /** The base PID type and the national type recorded in docs/eudi-wallet-spec-notes.md §7.1. */
        public static final List<String> DEFAULT_SD_JWT_VCTS = List.of("urn:eudi:pid:1", "urn:eudi:pid:de:1");
        public static final List<String> DEFAULT_REQUESTED_CLAIMS = List.of("given_name", "family_name", "birthdate");

        public Pid {
            sdJwtVcts = sdJwtVcts == null ? DEFAULT_SD_JWT_VCTS : copy(sdJwtVcts);
            mdocDoctype = isBlank(mdocDoctype) ? PidQuerySpec.DEFAULT_MDOC_DOCTYPE : mdocDoctype.trim();
            requestedClaims = requestedClaims == null ? DEFAULT_REQUESTED_CLAIMS : copy(requestedClaims);
        }

        /** What {@link DcqlQueryBuilder#pidQuery} requests. */
        public PidQuerySpec toQuerySpec() {
            return new PidQuerySpec(sdJwtVcts, mdocDoctype, requestedClaims);
        }

        /** The {@code acceptedVcts} of the SD-JWT {@link VerificationContext}: the query's {@code vct_values}. */
        public Set<String> acceptedVcts() {
            return Collections.unmodifiableSet(new LinkedHashSet<>(toQuerySpec().sdJwtVcts()));
        }

        /** The {@code acceptedDoctype} of the mdoc {@link VerificationContext}: the query's {@code doctype_value}. */
        public String acceptedDoctype() {
            return toQuerySpec().mdocDoctype();
        }
    }

    /**
     * Token Status List enforcement (spec §7.6).
     *
     * @param required        a credential without {@code status} is refused (default {@code false})
     * @param onUnavailable   default {@link StatusPolicy.OnUnavailable#FAIL_CLOSED}
     * @param maxCacheSeconds 0–900 (default 900)
     * @param allowedHosts    status list host names; empty means any https host
     */
    public record StatusList(boolean required, StatusPolicy.OnUnavailable onUnavailable, Integer maxCacheSeconds,
                             List<String> allowedHosts) {

        public static final int DEFAULT_MAX_CACHE_SECONDS = 900;

        public StatusList {
            onUnavailable = onUnavailable == null ? StatusPolicy.OnUnavailable.FAIL_CLOSED : onUnavailable;
            maxCacheSeconds = maxCacheSeconds == null ? DEFAULT_MAX_CACHE_SECONDS : maxCacheSeconds;
            allowedHosts = allowedHosts == null ? List.of() : copy(allowedHosts);
        }

        /** The policy {@link io.helixiam.authorization.federation.wallet.status.TokenStatusListClient} enforces. */
        public StatusPolicy toStatusPolicy() {
            return new StatusPolicy(required, onUnavailable, Duration.ofSeconds(maxCacheSeconds), allowedHosts);
        }
    }

    /**
     * How the Helix subject is derived (maintainer decision 1: administrative number, else an explicit link).
     *
     * @param strategy               default {@link Strategy#ADMINISTRATIVE_NUMBER}
     * @param acknowledgeWeakSubject the admin accepts the attribute-tuple link fallback and its residual risk
     *
     * <p><b>Warning (no validator warnings channel exists, so it is documented here and in
     * docs/eudi-wallet-spec-notes.md):</b> the attribute tuple's field set follows {@code pid.requestedClaims}: adding
     * or removing {@code place_of_birth} there changes every tuple subject of this provider and orphans its existing
     * tuple links (users must link their wallet again). Administrative-number subjects are not affected.
     */
    public record Subject(Strategy strategy, boolean acknowledgeWeakSubject) {

        /** {@code NONE} (verify-only step-up) is out of this plan; the validator refuses it. */
        public enum Strategy { ADMINISTRATIVE_NUMBER, ATTRIBUTE_TUPLE, NONE }

        public Subject {
            strategy = strategy == null ? Strategy.ADMINISTRATIVE_NUMBER : strategy;
        }
    }

    /**
     * Parser bounds. {@code maxJwtBytes} caps a whole presentation (the response JWE and each JWT / SD-JWT in it);
     * the CBOR bounds default to {@link CborLimits#DEFAULTS}.
     */
    public record Limits(Integer maxJwtBytes, Integer cborMaxDepth, Integer cborMaxItems, Integer cborMaxBytes) {

        public static final int DEFAULT_MAX_JWT_BYTES = 64 * 1024;

        public Limits {
            maxJwtBytes = maxJwtBytes == null ? DEFAULT_MAX_JWT_BYTES : maxJwtBytes;
            cborMaxDepth = cborMaxDepth == null ? CborLimits.DEFAULTS.maxDepth() : cborMaxDepth;
            cborMaxItems = cborMaxItems == null ? CborLimits.DEFAULTS.maxItems() : cborMaxItems;
            cborMaxBytes = cborMaxBytes == null ? CborLimits.DEFAULTS.maxBytes() : cborMaxBytes;
        }

        /** @throws IllegalArgumentException when a CBOR bound is not positive (the validator reports it first) */
        public CborLimits cborLimits() {
            return new CborLimits(cborMaxDepth, cborMaxItems, cborMaxBytes);
        }
    }

    // ------------------------------------------------------------------------------------------------ stored form

    /** A config from the stored flat map; {@code alias} and {@code displayName} are read from the map. */
    public static WalletProviderConfig fromStored(final Map<String, String> stored) {
        final Map<String, String> c = stored == null ? Map.of() : stored;
        return fromStored(c.get("alias"), c.get("displayName"), c);
    }

    /**
     * A config from a stored identity provider: its alias and display name plus the flat settings map (see the class
     * comment).
     *
     * @throws WalletConfigFormatException carrying every malformed field (list, number, boolean or enum value); the
     *                                     messages name the key and never echo the value
     */
    public static WalletProviderConfig fromStored(final String alias, final String displayName,
                                                  final Map<String, String> stored) {
        final Parsed parsed = parseStored(alias, displayName, stored);
        if (!parsed.fieldErrors().isEmpty()) {
            throw new WalletConfigFormatException(parsed.fieldErrors());
        }
        return parsed.config();
    }

    /**
     * Reads the stored map without throwing: a malformed field is recorded in {@code fieldErrors} and takes its
     * default in {@code config}.
     */
    static Parsed parseStored(final String alias, final String displayName, final Map<String, String> stored) {
        final Reader r = new Reader(stored == null ? Map.of() : stored);
        final WalletProviderConfig config = new WalletProviderConfig(alias, displayName,
                r.enumValue("clientIdScheme", ClientIdScheme.class, ClientIdScheme::value),
                r.text("clientIdHost"), r.text("accessCertificateChain"), r.text("accessKeyRef"),
                r.text("accessCertificateKeyRef"), r.text("accessCertificatePrivateKey"),
                r.text("registrationCertificate"), r.text("invocationScheme"),
                r.enumValue("responseMode", ResponseMode.class, ResponseMode::value),
                r.enumValue("requestUriMethod", RequestUriMethod.class, RequestUriMethod::value),
                r.integer("transactionTtlSeconds"), r.list("credentialFormats"),
                new Pid(r.list("pid.sdJwtVcts"), r.text("pid.mdocDoctype"), r.list("pid.requestedClaims")),
                r.list("customCredentialQueries"), r.text("trustAnchors"),
                r.enumValue("revocationChecking", TrustAnchors.RevocationMode.class, Enum::name),
                new StatusList(r.bool("statusList.required"),
                        r.enumValue("statusList.onUnavailable", StatusPolicy.OnUnavailable.class, Enum::name),
                        r.integer("statusList.maxCacheSeconds"), r.list("statusList.allowedHosts")),
                new Subject(r.enumValue("subject.strategy", Subject.Strategy.class, Enum::name),
                        r.bool("subject.acknowledgeWeakSubject")),
                r.text("minimumLoa"), r.integer("clockSkewSeconds"), r.bool("allowLegacyVcSdJwtTyp"),
                new Limits(r.integer("limits.maxJwtBytes"), r.integer("limits.cborMaxDepth"),
                        r.integer("limits.cborMaxItems"), r.integer("limits.cborMaxBytes")));
        return new Parsed(config, Collections.unmodifiableMap(r.errors));
    }

    /** A stored map read leniently: the config (malformed fields defaulted) and field → message for each one. */
    record Parsed(WalletProviderConfig config, Map<String, String> fieldErrors) {
    }

    /**
     * The plain (non-secret) stored settings; {@link #fromStored} round-trips them together with
     * {@link #storedSecrets}. Secret keys ({@link ProviderSecretKeys#isSecret}) are never in this map, so returning it
     * from an admin API or writing it to {@code config_json} cannot leak the dev private key.
     */
    public Map<String, String> toStored() {
        final Map<String, String> plain = new LinkedHashMap<>();
        allStored().forEach((k, v) -> {
            if (!ProviderSecretKeys.isSecret(SECRET_PROTOCOL, k)) {
                plain.put(k, v);
            }
        });
        return plain;
    }

    /**
     * The secret stored settings (today only the dev-only {@code accessCertificatePrivateKey}), to be written only to
     * the encrypted {@code secret_json} ({@link ProviderSecretKeys}); empty when none is set.
     */
    public Map<String, String> storedSecrets() {
        final Map<String, String> secrets = new LinkedHashMap<>();
        allStored().forEach((k, v) -> {
            if (ProviderSecretKeys.isSecret(SECRET_PROTOCOL, k)) {
                secrets.put(k, v);
            }
        });
        return secrets;
    }

    private Map<String, String> allStored() {
        final Map<String, String> m = new LinkedHashMap<>();
        put(m, "alias", alias);
        put(m, "displayName", displayName);
        put(m, "clientIdScheme", clientIdScheme.value());
        put(m, "clientIdHost", clientIdHost);
        put(m, "accessCertificateChain", accessCertificateChain);
        put(m, "accessKeyRef", accessKeyRef);
        put(m, "accessCertificateKeyRef", accessCertificateKeyRef);
        put(m, "accessCertificatePrivateKey", accessCertificatePrivateKey);
        put(m, "registrationCertificate", registrationCertificate);
        put(m, "invocationScheme", invocationScheme);
        put(m, "responseMode", responseMode.value());
        put(m, "requestUriMethod", requestUriMethod.value());
        put(m, "transactionTtlSeconds", String.valueOf(transactionTtlSeconds));
        put(m, "credentialFormats", json(credentialFormats));
        put(m, "pid.sdJwtVcts", json(pid.sdJwtVcts()));
        put(m, "pid.mdocDoctype", pid.mdocDoctype());
        put(m, "pid.requestedClaims", json(pid.requestedClaims()));
        put(m, "customCredentialQueries", json(customCredentialQueries));
        put(m, "trustAnchors", trustAnchors);
        put(m, "revocationChecking", revocationChecking.name());
        put(m, "statusList.required", String.valueOf(statusList.required()));
        put(m, "statusList.onUnavailable", statusList.onUnavailable().name());
        put(m, "statusList.maxCacheSeconds", String.valueOf(statusList.maxCacheSeconds()));
        put(m, "statusList.allowedHosts", json(statusList.allowedHosts()));
        put(m, "subject.strategy", subject.strategy().name());
        put(m, "subject.acknowledgeWeakSubject", String.valueOf(subject.acknowledgeWeakSubject()));
        put(m, "minimumLoa", minimumLoa);
        put(m, "clockSkewSeconds", String.valueOf(clockSkewSeconds));
        put(m, "allowLegacyVcSdJwtTyp", String.valueOf(allowLegacyVcSdJwtTyp));
        put(m, "limits.maxJwtBytes", String.valueOf(limits.maxJwtBytes()));
        put(m, "limits.cborMaxDepth", String.valueOf(limits.cborMaxDepth()));
        put(m, "limits.cborMaxItems", String.valueOf(limits.cborMaxItems()));
        put(m, "limits.cborMaxBytes", String.valueOf(limits.cborMaxBytes()));
        return m;
    }

    /** Never shows the dev-only private key; PEM certificate bundles are summarised. */
    @Override
    public String toString() {
        return "WalletProviderConfig[alias=" + alias + ", clientIdScheme=" + clientIdScheme.value() + ", clientIdHost="
                + clientIdHost + ", accessKeyRef=" + accessKeyRef + ", accessCertificatePrivateKey="
                + (accessCertificatePrivateKey == null ? "null" : "[REDACTED]") + ", invocationScheme="
                + invocationScheme + ", responseMode=" + responseMode.value() + ", credentialFormats="
                + credentialFormats + ", pid=" + pid + ", statusList=" + statusList + ", subject=" + subject
                + ", minimumLoa=" + minimumLoa + ", transactionTtlSeconds=" + transactionTtlSeconds + "]";
    }

    // ------------------------------------------------------------------------------------------------ helpers

    private static boolean isBlank(final String v) {
        return v == null || v.isBlank();
    }

    private static void put(final Map<String, String> m, final String key, final String value) {
        if (value != null) {
            m.put(key, value);
        }
    }

    /** A copy that keeps null elements (reported by the validator) and cannot be modified. */
    private static List<String> copy(final List<String> values) {
        return Collections.unmodifiableList(new ArrayList<>(values));
    }

    /** Reads stored values; a malformed one is recorded (first message per key) and read as absent. */
    private static final class Reader {
        private final Map<String, String> c;
        private final Map<String, String> errors = new LinkedHashMap<>();

        Reader(final Map<String, String> c) {
            this.c = c;
        }

        private <T> T fail(final String key, final String message) {
            errors.putIfAbsent(key, message);
            return null;
        }

        String text(final String key) {
            final String v = c.get(key);
            return isBlank(v) ? null : v;
        }

        Integer integer(final String key) {
            final String v = text(key);
            if (v == null) {
                return null;
            }
            try {
                return Integer.valueOf(v.trim());
            } catch (final NumberFormatException e) {
                return fail(key, key + " must be a whole number");
            }
        }

        boolean bool(final String key) {
            final String v = text(key);
            if (v == null || "false".equalsIgnoreCase(v.trim())) {
                return false;
            }
            if ("true".equalsIgnoreCase(v.trim())) {
                return true;
            }
            fail(key, key + " must be true or false");
            return false;
        }

        <E extends Enum<E>> E enumValue(final String key, final Class<E> type, final Function<E, String> wire) {
            final String v = text(key);
            if (v == null) {
                return null;
            }
            final String wanted = v.trim();
            final List<String> allowed = new ArrayList<>();
            for (final E e : type.getEnumConstants()) {
                if (e.name().equalsIgnoreCase(wanted) || wire.apply(e).equalsIgnoreCase(wanted)) {
                    return e;
                }
                allowed.add(wire.apply(e));
            }
            return fail(key, key + " must be one of " + allowed);
        }

        List<String> list(final String key) {
            final String v = text(key);
            if (v == null) {
                return null;
            }
            final JsonNode node;
            try {
                node = JSON.readTree(v);
            } catch (final JsonProcessingException e) {
                return fail(key, key + " must be a JSON array of strings");
            }
            if (node == null || !node.isArray()) {
                return fail(key, key + " must be a JSON array of strings");
            }
            final List<String> out = new ArrayList<>();
            for (final JsonNode element : node) {
                if (!element.isTextual()) {
                    return fail(key, key + " must be a JSON array of strings");
                }
                out.add(element.textValue());
            }
            return out;
        }
    }

    private static String json(final List<String> values) {
        try {
            return JSON.writeValueAsString(values);
        } catch (final JsonProcessingException e) {
            throw new IllegalStateException("Could not encode a list", e);
        }
    }
}
