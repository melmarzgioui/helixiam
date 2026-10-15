/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.status;

import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import io.helixiam.common.json.JsonMappers;
import tools.jackson.databind.json.JsonMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.authorization.federation.wallet.trust.IssuerTrustValidator;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;
import io.helixiam.authorization.federation.wallet.trust.ValidatedChain;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * A signature-verified Status List Token (draft-ietf-oauth-status-list-21 §5): its subject, times, {@code bits} and the
 * inflated status list. Two forms:
 * <ul>
 *   <li><b>JWT</b> ({@code typ statuslist+jwt}, §5.1): {@code alg} ES256/384/512 or PS256/384/512, the signer from the
 *       {@code x5c} header (HAIP §6.1), {@code sub}, {@code iat}, optional {@code exp} / {@code ttl}, and
 *       {@code status_list} {@code {bits, lst}} with {@code lst} the base64url zlib-compressed list. Header and payload
 *       are read with a strict JSON reader (duplicate members refused).</li>
 *   <li><b>CWT</b> (§5.2, the ISO mdoc form): COSE_Sign1_Tagged, parsed and verified by {@link StatusListCwt}.</li>
 * </ul>
 *
 * <p>In both forms the signer chain is validated by {@link IssuerTrustValidator} against the credential's own
 * {@link TrustAnchors} at {@code now}; {@code iat} must not be in the future beyond the clock skew; {@code bits} must be
 * 1, 2, 4 or 8; the list is inflated with a {@value #MAX_INFLATED_BYTES}-byte cap ({@code LIMIT_EXCEEDED}). Every
 * failure is a {@link WalletVerificationException} with a safe detail. Checks that depend on the request ({@code sub}
 * against the referenced {@code uri}, {@code exp} at use time) are the caller's.
 */
public final class StatusListToken {

    /** The largest inflated status list (spec limit: decompressed &le; 2 MB). */
    public static final int MAX_INFLATED_BYTES = 2 * 1024 * 1024;
    /** Clock skew tolerated on {@code iat} and {@code exp}. */
    public static final Duration CLOCK_SKEW = Duration.ofSeconds(60);

    private static final String JWT_TYP = "statuslist+jwt";
    private static final Set<JWSAlgorithm> ALLOWED_JWS = Set.of(JWSAlgorithm.ES256, JWSAlgorithm.ES384,
            JWSAlgorithm.ES512, JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512);
    private static final Set<JWSAlgorithm> RSA_PSS = Set.of(JWSAlgorithm.PS256, JWSAlgorithm.PS384,
            JWSAlgorithm.PS512);
    private static final Set<Long> ALLOWED_BITS = Set.of(1L, 2L, 4L, 8L);
    private static final int MIN_RSA_BITS = 2048;
    private static final long MAX_EPOCH_SECONDS = 100_000_000_000_000L;

    private static final ObjectMapper STRICT_JSON = JsonMappers.jackson2Compatible(JsonMapper.builder(
                    JsonMappers.factoryBuilder()
                            .streamReadConstraints(JsonMappers.readConstraints().maxNestingDepth(16).build())
                            .build())
                    .configureForJackson2())
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.USE_LONG_FOR_INTS)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .build();

    private final String subject;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private final Duration ttl;
    private final int bits;
    private final byte[] list;
    private final ValidatedChain signer;

    private StatusListToken(final String subject, final Instant issuedAt, final Instant expiresAt,
            final Duration ttl, final int bits, final byte[] list, final ValidatedChain signer) {
        this.signer = signer;
        this.subject = subject;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.ttl = ttl;
        this.bits = bits;
        this.list = list;
    }

    /** The signer's chain as PKIX validated it (never the presented {@code x5c} / {@code x5chain}). */
    public ValidatedChain signer() {
        return signer;
    }

    /** {@code sub}: the URI this list claims to be. */
    public String subject() {
        return subject;
    }

    public Instant issuedAt() {
        return issuedAt;
    }

    /** {@code exp}, or null when absent. */
    public Instant expiresAt() {
        return expiresAt;
    }

    /** {@code ttl}, or null when absent. */
    public Duration ttl() {
        return ttl;
    }

    public int bits() {
        return bits;
    }

    /** Size of the decoded (inflated) list in bytes: what this token costs in {@link StatusListCache}. */
    public int decodedSize() {
        return list.length;
    }

    /** True when {@code exp} is present and passed at {@code now} (beyond {@link #CLOCK_SKEW}). */
    public boolean isExpiredAt(final Instant now) {
        return expiresAt != null && now.isAfter(expiresAt.plus(CLOCK_SKEW));
    }

    /** The status value at {@code idx}; {@code INVALID_RESPONSE} when the index is outside the list (§8.3 step 6). */
    public int statusAt(final int idx) {
        return statusAt(list, bits, idx);
    }

    // ------------------------------------------------------------------------------------------- JWT

    /** Parses and verifies a Status List Token in JWT form. */
    public static StatusListToken fromJwt(final String compact, final TrustAnchors anchors, final Instant now,
            final IssuerTrustValidator trust) {
        final String[] parts = compact.trim().split("\\.", -1);
        if (parts.length != 3) {
            throw invalid("Status List Token is not a compact JWS");
        }
        final Map<String, Object> header = json(parts[0], "header");
        final Map<String, Object> claims = json(parts[1], "payload");
        if (header.containsKey("crit") || header.containsKey("b64")) {
            throw invalid("Status List Token uses an unsupported header parameter");
        }
        if (!(header.get("typ") instanceof String typ) || !typIs(typ)) {
            throw new WalletVerificationException(WalletErrorCode.UNSUPPORTED_FORMAT,
                    "Status List Token typ is not statuslist+jwt");
        }
        if (!(header.get("alg") instanceof String algName) || !ALLOWED_JWS.contains(JWSAlgorithm.parse(algName))) {
            throw new WalletVerificationException(WalletErrorCode.ALGORITHM_NOT_ALLOWED,
                    "Status List Token alg is not allowed");
        }
        final JWSAlgorithm alg = JWSAlgorithm.parse(algName);
        final ValidatedChain chain = trust.validateChain(x5c(header.get("x5c")), anchors, now);
        final X509Certificate leaf = chain.leaf();
        final JWSVerifier verifier = jwsVerifier(leaf.getPublicKey(), alg);
        try {
            if (!JWSObject.parse(compact.trim()).verify(verifier)) {
                throw signatureInvalid();
            }
        } catch (final ParseException e) {
            throw invalid("Status List Token cannot be parsed");
        } catch (final JOSEException e) {
            throw signatureInvalid();
        }

        final String sub = claims.get("sub") instanceof String s ? s : null;
        final Instant iat = claims.containsKey("iat") ? numericDate(claims.get("iat"), "iat") : null;
        final Instant exp = claims.containsKey("exp") ? numericDate(claims.get("exp"), "exp") : null;
        final Duration ttl = claims.containsKey("ttl") ? ttl(claims.get("ttl")) : null;
        if (!(claims.get("status_list") instanceof Map<?, ?> statusList)
                || !(statusList.get("bits") instanceof Long bitsValue)
                || !(statusList.get("lst") instanceof String lst)) {
            throw invalid("Status List Token status_list is malformed");
        }
        final byte[] compressed;
        try {
            compressed = Base64.getUrlDecoder().decode(lst);
        } catch (final IllegalArgumentException e) {
            throw invalid("Status List Token lst is not base64url");
        }
        return build(sub, iat, exp, ttl, bitsValue, compressed, now, chain);
    }

    // ------------------------------------------------------------------------------------------- CWT

    /** Parses and verifies a Status List Token in CWT form (COSE_Sign1_Tagged); see {@link StatusListCwt}. */
    public static StatusListToken fromCwt(final byte[] cwt, final TrustAnchors anchors, final Instant now,
            final IssuerTrustValidator trust) {
        return StatusListCwt.parse(cwt, anchors, now, trust);
    }

    // ------------------------------------------------------------------------------------------- list

    /**
     * zlib-inflates {@code compressed} (RFC 1950 / 1951), refusing more than {@value #MAX_INFLATED_BYTES} bytes
     * ({@code LIMIT_EXCEEDED}, checked while inflating so a bomb is never materialised), truncated input, a preset
     * dictionary and trailing bytes ({@code INVALID_RESPONSE}).
     */
    public static byte[] inflate(final byte[] compressed) {
        if (compressed == null || compressed.length == 0) {
            throw invalid("status list is empty");
        }
        final Inflater inflater = new Inflater();
        try {
            inflater.setInput(compressed);
            final ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(MAX_INFLATED_BYTES,
                    compressed.length * 4));
            final byte[] buffer = new byte[16 * 1024];
            while (!inflater.finished()) {
                final int n = inflater.inflate(buffer);
                if (n == 0 && (inflater.needsInput() || inflater.needsDictionary())) {
                    throw invalid("status list is not a complete zlib stream");
                }
                if (out.size() + n > MAX_INFLATED_BYTES) {
                    throw new WalletVerificationException(WalletErrorCode.LIMIT_EXCEEDED,
                            "status list exceeds " + MAX_INFLATED_BYTES + " bytes inflated");
                }
                out.write(buffer, 0, n);
            }
            if (inflater.getRemaining() > 0) {
                throw invalid("status list has trailing bytes");
            }
            return out.toByteArray();
        } catch (final DataFormatException e) {
            throw invalid("status list is not zlib");
        } finally {
            inflater.end();
        }
    }

    /**
     * The status at {@code idx} of an inflated list with {@code bits} per entry (draft §4.1, LSB first):
     * {@code (list[idx * bits / 8] >> ((idx % (8 / bits)) * bits)) & ((1 << bits) - 1)}.
     */
    static int statusAt(final byte[] list, final int bits, final int idx) {
        final long bit = (long) idx * bits;
        if (idx < 0 || bit / 8 >= list.length) {
            throw invalid("status index is outside the status list");
        }
        return ((list[(int) (bit / 8)] & 0xff) >> ((idx % (8 / bits)) * bits)) & ((1 << bits) - 1);
    }

    // ------------------------------------------------------------------------------------------- helpers

    static StatusListToken build(final String sub, final Instant iat, final Instant exp, final Duration ttl,
            final long bits, final byte[] compressed, final Instant now, final ValidatedChain chain) {
        if (sub == null || sub.isBlank()) {
            throw invalid("Status List Token has no sub");
        }
        if (iat == null) {
            throw invalid("Status List Token has no iat");
        }
        if (iat.isAfter(now.plus(CLOCK_SKEW))) {
            throw invalid("Status List Token iat is in the future");
        }
        if (!ALLOWED_BITS.contains(bits)) {
            throw invalid("Status List Token bits is not 1, 2, 4 or 8");
        }
        return new StatusListToken(sub, iat, exp, ttl, (int) bits, inflate(compressed), chain);
    }

    private static boolean typIs(final String typ) {
        final String t = typ.toLowerCase(Locale.ROOT);
        return t.equals(JWT_TYP) || t.equals("application/" + JWT_TYP);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> json(final String segment, final String what) {
        try {
            final Object parsed = STRICT_JSON.readValue(Base64.getUrlDecoder().decode(segment), Object.class);
            if (parsed instanceof Map<?, ?> map) {
                return (Map<String, Object>) map;
            }
        } catch (final tools.jackson.core.JacksonException | IllegalArgumentException e) {
            // fall through: duplicate member, malformed JSON or base64url
        }
        throw invalid("Status List Token " + what + " is not a strict JSON object");
    }

    private static List<X509Certificate> x5c(final Object value) {
        if (!(value instanceof List<?> encoded) || encoded.isEmpty()) {
            throw new WalletVerificationException(WalletErrorCode.ISSUER_UNTRUSTED, "Status List Token has no x5c");
        }
        final List<byte[]> der = new ArrayList<>(encoded.size());
        for (final Object e : encoded) {
            if (!(e instanceof String b64)) {
                throw new WalletVerificationException(WalletErrorCode.ISSUER_UNTRUSTED, "x5c entry is not a string");
            }
            try {
                der.add(Base64.getDecoder().decode(b64)); // x5c: standard base64 of DER (RFC 7515 §4.1.6)
            } catch (final IllegalArgumentException ex) {
                throw new WalletVerificationException(WalletErrorCode.ISSUER_UNTRUSTED, "x5c entry is not base64");
            }
        }
        return certificates(der);
    }

    private static List<X509Certificate> certificates(final List<byte[]> der) {
        try {
            final CertificateFactory factory = CertificateFactory.getInstance("X.509");
            final List<X509Certificate> chain = new ArrayList<>(der.size());
            for (final byte[] d : der) {
                chain.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(d)));
            }
            return chain;
        } catch (final CertificateException | ClassCastException e) {
            throw new WalletVerificationException(WalletErrorCode.ISSUER_UNTRUSTED,
                    "Status List Token certificate cannot be parsed");
        }
    }

    /** A JWS verifier when {@code alg} fits {@code key} (its EC curve for ES*, RSA &ge; 2048 for PS*). */
    private static JWSVerifier jwsVerifier(final PublicKey key, final JWSAlgorithm alg) {
        try {
            if (key instanceof ECPublicKey ec) {
                final ECDSAVerifier v = new ECDSAVerifier(ec);
                if (v.supportedJWSAlgorithms().contains(alg)) {
                    return v;
                }
            } else if (key instanceof RSAPublicKey rsa && rsa.getModulus().bitLength() >= MIN_RSA_BITS
                    && RSA_PSS.contains(alg)) {
                return new RSASSAVerifier(rsa);
            }
        } catch (final JOSEException e) {
            // fall through
        }
        throw new WalletVerificationException(WalletErrorCode.ALGORITHM_NOT_ALLOWED,
                "Status List Token alg does not fit the certificate key");
    }

    static Instant numericDate(final Object value, final String name) {
        final long seconds;
        if (value instanceof Long l) {
            seconds = l;
        } else if (value instanceof Double d && Double.isFinite(d) && Math.abs(d) < MAX_EPOCH_SECONDS) {
            seconds = (long) Math.floor(d);
        } else {
            throw invalid("Status List Token " + name + " is not a NumericDate");
        }
        if (Math.abs(seconds) >= MAX_EPOCH_SECONDS) {
            throw invalid("Status List Token " + name + " is out of range");
        }
        return Instant.ofEpochSecond(seconds);
    }

    /** {@code ttl}: a positive number of seconds (§5.1). */
    static Duration ttl(final Object value) {
        if (value instanceof Long l && l > 0 && l < MAX_EPOCH_SECONDS) {
            return Duration.ofSeconds(l);
        }
        if (value instanceof Double d && Double.isFinite(d) && d > 0 && d < MAX_EPOCH_SECONDS) {
            return Duration.ofMillis((long) (d * 1000));
        }
        throw invalid("Status List Token ttl is not a positive number");
    }

    static WalletVerificationException signatureInvalid() {
        return new WalletVerificationException(WalletErrorCode.ISSUER_SIGNATURE_INVALID,
                "Status List Token signature is invalid");
    }

    static WalletVerificationException invalid(final String safeDetail) {
        return new WalletVerificationException(WalletErrorCode.INVALID_RESPONSE, safeDetail);
    }

    @Override
    public String toString() {
        return "StatusListToken[sub=" + subject + ", bits=" + bits + ", entries=" + (list.length * 8 / bits) + "]";
    }
}
