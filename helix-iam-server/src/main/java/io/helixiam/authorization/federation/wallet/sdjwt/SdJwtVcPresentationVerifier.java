/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.sdjwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import io.helixiam.authorization.federation.wallet.PresentationVerifier;
import io.helixiam.authorization.federation.wallet.StrictJson;
import io.helixiam.authorization.federation.wallet.VerificationContext;
import io.helixiam.authorization.federation.wallet.VerifiedPresentation;
import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.authorization.federation.wallet.status.CredentialIssuer;
import io.helixiam.authorization.federation.wallet.status.StatusEvaluator;
import io.helixiam.authorization.federation.wallet.status.StatusCheck;
import io.helixiam.authorization.federation.wallet.status.StatusReference;
import io.helixiam.authorization.federation.wallet.trust.IssuerTrustValidator;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Verifies an SD-JWT VC presentation ({@code dc+sd-jwt}, docs/eudi-wallet-spec-notes.md §3, §4) and returns only the
 * disclosed PID claims plus the issuer certificate's identity. Every failure is a {@link WalletVerificationException};
 * no partial result is ever returned. Nothing is logged here and no exception detail carries presentation content.
 *
 * <p>Checks, in this order (fail closed, RFC 9901 §7.1 / §7.3):
 * <ol>
 *   <li>split ({@link SdJwt#parse}; at most {@code maxDisclosures} disclosures and {@code maxPresentationBytes} for the
 *       whole presentation);</li>
 *   <li>the issuer JWT header and payload are decoded with a strict JSON parser: a repeated member name anywhere in
 *       the header or payload is {@code INVALID_RESPONSE} (Nimbus would silently keep the last value; a signed but
 *       ambiguous payload must not be interpreted). A {@code crit} or {@code b64} header is refused;</li>
 *   <li>{@code typ} is {@code dc+sd-jwt} ({@code vc+sd-jwt} only with {@code allowLegacyVcSdJwtTyp}); compared
 *       case-insensitively with an optional {@code application/} prefix (RFC 7515 §4.1.9); else
 *       {@code UNSUPPORTED_FORMAT};</li>
 *   <li>{@code alg} in {ES256, ES384, ES512, PS256, PS384, PS512}: never {@code none}, {@code HS*} or {@code RS*};
 *       else {@code ALGORITHM_NOT_ALLOWED};</li>
 *   <li>{@code x5c} chain via {@link IssuerTrustValidator} against the configured anchors at {@code context.now}
 *       (missing {@code x5c}: {@code ISSUER_UNTRUSTED}). Trust comes only from this chain: {@code iss} is never used to
 *       find keys and no issuer metadata is fetched;</li>
 *   <li>JWS signature with the leaf key: an {@code alg} that does not fit the key (curve, or EC vs RSA) is
 *       {@code ALGORITHM_NOT_ALLOWED}; a bad signature is {@code ISSUER_SIGNATURE_INVALID};</li>
 *   <li>{@code iss} is OPTIONAL and, when present, must be a string; {@code vct} is REQUIRED (a string) and it or one
 *       of {@code aka_vcts} must be in {@code acceptedVcts} ({@code VCT_NOT_ACCEPTED}); the first accepted of these
 *       ({@code vct} before {@code aka_vcts}) is the result's {@code credentialType}; {@code exp} (expired when
 *       {@code now >= exp + skew}: {@code CREDENTIAL_EXPIRED}), {@code nbf} and {@code iat} (in the future beyond the
 *       skew: {@code CREDENTIAL_NOT_YET_VALID}). All three are optional; when present they must be numbers;</li>
 *   <li>disclosures resolved with the payload's {@code _sd_alg} ({@link SdJwtDisclosures}); a claim that SD-JWT VC
 *       §2.2.2.3 forbids to disclose selectively ({@code iss nbf exp cnf vct vct#integrity aka_vcts status}) arriving
 *       through a disclosure, or holding an {@code _sd} member or {@code "..."} array digest at any depth (so no part
 *       of {@code status} or {@code cnf} can be withheld), is {@code DISCLOSURE_INVALID}; a selectively disclosed {@code iat} gets the same time
 *       check as a plain one;</li>
 *   <li>Key Binding JWT, always required (§7.3 step 1): absent, or no {@code cnf.jwk} in the credential:
 *       {@code HOLDER_BINDING_MISSING}. Then strict JSON as above; {@code typ} {@code kb+jwt}
 *       ({@code HOLDER_BINDING_INVALID}); {@code alg} allow-list ({@code ALGORITHM_NOT_ALLOWED}); signature with
 *       {@code cnf.jwk} (a public EC P-256/384/521 or RSA &ge; 2048 key; anything else, an {@code alg} that does not
 *       fit it, or a wrong signature: {@code HOLDER_BINDING_INVALID}); {@code aud} a single string equal to
 *       {@code clientId} ({@code AUDIENCE_MISMATCH}); {@code nonce} ({@code NONCE_MISMATCH}); {@code iat} REQUIRED and
 *       within the window below; optional {@code exp}/{@code nbf} honoured; {@code sd_hash} equal to
 *       {@link SdJwt#sdHash} under the payload's {@code _sd_alg} ({@code HOLDER_BINDING_INVALID});</li>
 *   <li>status: no {@code status} claim at all: {@code STATUS_REQUIRED} when {@code statusPolicy.required}, else
 *       accepted as {@code ABSENT} (the only way to {@code ABSENT}). A {@code status.status_list} reference goes to the
 *       {@link StatusEvaluator}, which must answer {@code VALID} or throw; its wallet exceptions pass through and any
 *       other answer is {@code STATUS_UNAVAILABLE} (never fail-open). A present {@code status} with no evaluable
 *       mechanism (no {@code status_list}, or only an unknown one), or an evaluator failing with a non-wallet
 *       exception, is <em>unavailable</em>: {@code STATUS_UNAVAILABLE} under {@code onUnavailable = FAIL_CLOSED} (also
 *       for a null policy), accepted as {@code UNAVAILABLE_ACCEPTED} under {@code FAIL_OPEN_WITH_AUDIT}. A malformed
 *       reference is {@code INVALID_RESPONSE};</li>
 *   <li>output.</li>
 * </ol>
 *
 * <p><b>KB-JWT {@code iat} window.</b> Future direction: at most {@code context.clockSkew} ahead of
 * {@code context.now}. Past direction: at most {@code kbMaxAge} (default 5 minutes, constructor-configurable) before
 * {@code context.now}; the skew is not added to the max age. Replay inside the window is stopped by the single-use
 * transaction nonce, not here.
 *
 * <p><b>Output claims.</b> The fully resolved payload minus the members that describe the credential rather than the
 * subject: {@code _sd, _sd_alg, cnf, status, iss, vct, vct#integrity, aka_vcts, iat, nbf, exp}. Everything else
 * (e.g. {@code sub}, {@code given_name}, {@code address}) is kept exactly as disclosed. The issuer identity is the leaf
 * certificate's subject DN (RFC 2253) and serial (lower-case hex).
 */
public final class SdJwtVcPresentationVerifier implements PresentationVerifier {

    public static final String FORMAT = "dc+sd-jwt";
    /** How old a KB-JWT {@code iat} may be. */
    public static final Duration DEFAULT_KB_MAX_AGE = Duration.ofMinutes(5);
    public static final int DEFAULT_MAX_DISCLOSURES = 100;
    /** Caps the whole presentation (issuer JWT, disclosures and KB-JWT), as ruled for "JWT 64 KB". */
    public static final int DEFAULT_MAX_PRESENTATION_BYTES = 64 * 1024;
    /** {@link VerifiedPresentation#statusResult()} when the credential carries no status reference. */
    public static final String STATUS_ABSENT = StatusCheck.ABSENT;
    /**
     * {@link VerifiedPresentation#statusResult()} when the status could not be evaluated and
     * {@code statusPolicy.onUnavailable} is {@code FAIL_OPEN_WITH_AUDIT}: accepted, and the caller must audit it.
     */
    public static final String STATUS_UNAVAILABLE_ACCEPTED = StatusCheck.UNAVAILABLE_ACCEPTED;

    private static final Set<String> OUTPUT_EXCLUDED = Set.of("_sd", "_sd_alg", "cnf", "status", "iss", "vct",
            "vct#integrity", "aka_vcts", "iat", "nbf", "exp");
    /** SD-JWT VC §2.2.2.3: these MUST NOT be selectively disclosed. */
    private static final Set<String> NEVER_DISCLOSED = Set.of("iss", "nbf", "exp", "cnf", "vct", "vct#integrity",
            "aka_vcts", "status");
    private static final Set<JWSAlgorithm> ALLOWED_ALGS = Set.of(JWSAlgorithm.ES256, JWSAlgorithm.ES384,
            JWSAlgorithm.ES512, JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512);
    private static final Set<JWSAlgorithm> RSA_PSS = Set.of(JWSAlgorithm.PS256, JWSAlgorithm.PS384,
            JWSAlgorithm.PS512);
    private static final Set<Curve> ALLOWED_CURVES = Set.of(Curve.P_256, Curve.P_384, Curve.P_521);
    private static final int MIN_RSA_BITS = 2048;
    /** |NumericDate| bound: far beyond any real date, far inside {@link Instant}'s range. */
    private static final long MAX_EPOCH_SECONDS = 100_000_000_000_000L;

    private final IssuerTrustValidator trust;
    private final StatusEvaluator status;
    private final Duration kbMaxAge;
    private final int maxDisclosures;
    private final int maxPresentationBytes;

    public SdJwtVcPresentationVerifier(final IssuerTrustValidator trust, final StatusEvaluator status) {
        this(trust, status, DEFAULT_KB_MAX_AGE, DEFAULT_MAX_DISCLOSURES, DEFAULT_MAX_PRESENTATION_BYTES);
    }

    public SdJwtVcPresentationVerifier(final IssuerTrustValidator trust, final StatusEvaluator status,
            final Duration kbMaxAge, final int maxDisclosures, final int maxPresentationBytes) {
        this.trust = Objects.requireNonNull(trust, "trust");
        this.status = Objects.requireNonNull(status, "status");
        this.kbMaxAge = Objects.requireNonNull(kbMaxAge, "kbMaxAge");
        if (kbMaxAge.isNegative() || kbMaxAge.isZero() || maxDisclosures < 0 || maxPresentationBytes <= 0) {
            throw new IllegalArgumentException("limits must be positive");
        }
        this.maxDisclosures = maxDisclosures;
        this.maxPresentationBytes = maxPresentationBytes;
    }

    @Override
    public String format() {
        return FORMAT;
    }

    @Override
    public VerifiedPresentation verify(final String rawPresentation, final VerificationContext context) {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(context.clientId(), "clientId");
        Objects.requireNonNull(context.nonce(), "nonce");
        Objects.requireNonNull(context.now(), "now");
        Objects.requireNonNull(context.anchors(), "anchors");
        Objects.requireNonNull(context.acceptedVcts(), "acceptedVcts");
        if (Objects.requireNonNull(context.clockSkew(), "clockSkew").isNegative()) {
            throw new IllegalArgumentException("clockSkew must not be negative");
        }
        try {
            return doVerify(rawPresentation, context);
        } catch (final WalletVerificationException e) {
            throw e;
        } catch (final RuntimeException e) {
            // Fail closed with a safe detail: library exception text may echo presentation content.
            throw fail(WalletErrorCode.INVALID_RESPONSE, "SD-JWT VC could not be verified");
        }
    }

    private VerifiedPresentation doVerify(final String raw, final VerificationContext ctx) {
        final SdJwt sdJwt = SdJwt.parse(raw, maxDisclosures, maxPresentationBytes);

        // ---- Issuer-signed JWT
        final Jws issuerJwt = Jws.decode(sdJwt.issuerJwt(), "Issuer-signed JWT");
        final Object typ = issuerJwt.header().get("typ");
        if (!typIs(typ, FORMAT) && !(ctx.allowLegacyVcSdJwtTyp() && typIs(typ, "vc+sd-jwt"))) {
            throw fail(WalletErrorCode.UNSUPPORTED_FORMAT, "Issuer-signed JWT typ is not dc+sd-jwt");
        }
        final JWSAlgorithm alg = allowedAlg(issuerJwt.header(), "Issuer-signed JWT");
        final List<X509Certificate> issuerChain = x5c(issuerJwt.header());
        final X509Certificate leaf = trust.validate(issuerChain, ctx.anchors(), ctx.now());
        final JWSVerifier issuerVerifier = verifierFor(leaf.getPublicKey(), alg);
        if (issuerVerifier == null) {
            throw fail(WalletErrorCode.ALGORITHM_NOT_ALLOWED, "Issuer-signed JWT alg does not fit the certificate key");
        }
        if (!issuerJwt.verify(issuerVerifier)) {
            throw fail(WalletErrorCode.ISSUER_SIGNATURE_INVALID, "Issuer-signed JWT signature is invalid");
        }

        final Map<String, Object> payload = issuerJwt.payload();
        if (payload.containsKey("iss") && !(payload.get("iss") instanceof String)) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "iss is not a string");
        }
        final String credentialType = checkVct(payload, ctx.acceptedVcts());
        checkCredentialTimes(payload, ctx);

        // ---- Disclosures
        final String sdAlg = SdJwtDisclosures.sdAlgOf(payload);
        final Map<String, Object> resolved = SdJwtDisclosures.resolve(payload, sdJwt.disclosures(), sdAlg);
        for (final String name : NEVER_DISCLOSED) {
            if (resolved.containsKey(name) && !payload.containsKey(name)) {
                throw fail(WalletErrorCode.DISCLOSURE_INVALID, "a claim that must not be selectively disclosed was");
            }
            if (containsDigests(payload.get(name))) {
                throw fail(WalletErrorCode.DISCLOSURE_INVALID, "a claim that must not be selectively disclosed has digests");
            }
        }
        if (resolved.containsKey("iat") && !payload.containsKey("iat")) {
            notInFuture(resolved.get("iat"), ctx, "iat");
        }

        // ---- Key Binding JWT
        if (sdJwt.keyBindingJwt() == null) {
            throw fail(WalletErrorCode.HOLDER_BINDING_MISSING, "no Key Binding JWT");
        }
        verifyKeyBinding(sdJwt, sdAlg, holderKey(payload), ctx);

        // ---- Status
        final String statusResult = checkStatus(payload, issuerChain, ctx);

        // ---- Output
        final Map<String, Object> claims = new LinkedHashMap<>(resolved);
        claims.keySet().removeAll(OUTPUT_EXCLUDED);
        return new VerifiedPresentation(FORMAT, credentialType, Collections.unmodifiableMap(claims),
                leaf.getSubjectX500Principal().getName(), leaf.getSerialNumber().toString(16), statusResult);
    }

    // ------------------------------------------------------------------------------------------- issuer claims

    /** Returns the type under which the credential is accepted: its {@code vct} if accepted, else the first accepted
     *  {@code aka_vcts} entry. */
    private static String checkVct(final Map<String, Object> payload, final Set<String> accepted) {
        if (!(payload.get("vct") instanceof String vct) || vct.isBlank()) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "vct is missing or not a string");
        }
        final List<String> types = new ArrayList<>();
        types.add(vct);
        if (payload.containsKey("aka_vcts")) {
            if (!(payload.get("aka_vcts") instanceof List<?> aka) || aka.isEmpty()) {
                throw fail(WalletErrorCode.INVALID_RESPONSE, "aka_vcts is not a non-empty array");
            }
            for (final Object a : aka) {
                if (!(a instanceof String s)) {
                    throw fail(WalletErrorCode.INVALID_RESPONSE, "aka_vcts holds a non-string");
                }
                types.add(s);
            }
        }
        return types.stream().filter(accepted::contains).findFirst()
                .orElseThrow(() -> fail(WalletErrorCode.VCT_NOT_ACCEPTED, "credential type is not accepted"));
    }

    private static void checkCredentialTimes(final Map<String, Object> payload, final VerificationContext ctx) {
        if (payload.containsKey("exp")) {
            final Instant exp = numericDate(payload.get("exp"), WalletErrorCode.INVALID_RESPONSE, "exp");
            if (!ctx.now().isBefore(exp.plus(ctx.clockSkew()))) {
                throw fail(WalletErrorCode.CREDENTIAL_EXPIRED, "credential expired");
            }
        }
        if (payload.containsKey("nbf")) {
            notInFuture(payload.get("nbf"), ctx, "nbf");
        }
        if (payload.containsKey("iat")) {
            notInFuture(payload.get("iat"), ctx, "iat");
        }
    }

    private static void notInFuture(final Object value, final VerificationContext ctx, final String name) {
        final Instant at = numericDate(value, WalletErrorCode.INVALID_RESPONSE, name);
        if (ctx.now().plus(ctx.clockSkew()).isBefore(at)) {
            throw fail(WalletErrorCode.CREDENTIAL_NOT_YET_VALID, "credential " + name + " is in the future");
        }
    }

    // ------------------------------------------------------------------------------------------- key binding

    /** {@code cnf.jwk} as a public key; absent: HOLDER_BINDING_MISSING, unusable: HOLDER_BINDING_INVALID. */
    private static PublicKey holderKey(final Map<String, Object> payload) {
        if (!(payload.get("cnf") instanceof Map<?, ?> cnf) || !cnf.containsKey("jwk")) {
            throw fail(WalletErrorCode.HOLDER_BINDING_MISSING, "credential has no cnf.jwk");
        }
        if (!(cnf.get("jwk") instanceof Map<?, ?> jwkJson)) {
            throw fail(WalletErrorCode.HOLDER_BINDING_INVALID, "cnf.jwk is not an object");
        }
        final JWK jwk;
        try {
            @SuppressWarnings("unchecked")
            final JWK parsed = JWK.parse((Map<String, Object>) jwkJson);
            jwk = parsed;
            if (!jwk.isPrivate()) {
                if (jwk instanceof ECKey ec && ALLOWED_CURVES.contains(ec.getCurve())) {
                    return ec.toECPublicKey();
                }
                if (jwk instanceof RSAKey rsa && rsa.size() >= MIN_RSA_BITS) {
                    return rsa.toRSAPublicKey();
                }
            }
        } catch (final ParseException | JOSEException | RuntimeException e) {
            throw fail(WalletErrorCode.HOLDER_BINDING_INVALID, "cnf.jwk is not a valid public JWK");
        }
        throw fail(WalletErrorCode.HOLDER_BINDING_INVALID,
                jwk.isPrivate() ? "cnf.jwk contains private key material" : "cnf.jwk key type or size not allowed");
    }

    private void verifyKeyBinding(final SdJwt sdJwt, final String sdAlg, final PublicKey holderKey,
            final VerificationContext ctx) {
        final Jws kb = Jws.decode(sdJwt.keyBindingJwt(), "Key Binding JWT");
        if (!typIs(kb.header().get("typ"), "kb+jwt")) {
            throw fail(WalletErrorCode.HOLDER_BINDING_INVALID, "Key Binding JWT typ is not kb+jwt");
        }
        final JWSAlgorithm alg = allowedAlg(kb.header(), "Key Binding JWT");
        final JWSVerifier kbVerifier = verifierFor(holderKey, alg);
        if (kbVerifier == null || !kb.verify(kbVerifier)) {
            throw fail(WalletErrorCode.HOLDER_BINDING_INVALID, "Key Binding JWT signature is invalid");
        }
        final Map<String, Object> claims = kb.payload();
        if (!(claims.get("aud") instanceof String aud) || !aud.equals(ctx.clientId())) {
            throw fail(WalletErrorCode.AUDIENCE_MISMATCH, "Key Binding JWT aud does not match");
        }
        if (!(claims.get("nonce") instanceof String nonce) || !constantTimeEquals(nonce, ctx.nonce())) {
            throw fail(WalletErrorCode.NONCE_MISMATCH, "Key Binding JWT nonce does not match");
        }
        if (!claims.containsKey("iat")) {
            throw fail(WalletErrorCode.HOLDER_BINDING_INVALID, "Key Binding JWT has no iat");
        }
        final Instant iat = numericDate(claims.get("iat"), WalletErrorCode.HOLDER_BINDING_INVALID, "iat");
        if (iat.isAfter(ctx.now().plus(ctx.clockSkew())) || iat.isBefore(ctx.now().minus(kbMaxAge))) {
            throw fail(WalletErrorCode.HOLDER_BINDING_INVALID, "Key Binding JWT iat is outside the window");
        }
        if (claims.containsKey("exp")) {
            final Instant exp = numericDate(claims.get("exp"), WalletErrorCode.HOLDER_BINDING_INVALID, "exp");
            if (!ctx.now().isBefore(exp.plus(ctx.clockSkew()))) {
                throw fail(WalletErrorCode.HOLDER_BINDING_INVALID, "Key Binding JWT expired");
            }
        }
        if (claims.containsKey("nbf")) {
            final Instant nbf = numericDate(claims.get("nbf"), WalletErrorCode.HOLDER_BINDING_INVALID, "nbf");
            if (ctx.now().plus(ctx.clockSkew()).isBefore(nbf)) {
                throw fail(WalletErrorCode.HOLDER_BINDING_INVALID, "Key Binding JWT not yet valid");
            }
        }
        if (!(claims.get("sd_hash") instanceof String sdHash) || !constantTimeEquals(sdHash, sdJwt.sdHash(sdAlg))) {
            throw fail(WalletErrorCode.HOLDER_BINDING_INVALID, "Key Binding JWT sd_hash does not match");
        }
    }

    // ------------------------------------------------------------------------------------------- status

    /** Status policy via the shared {@link StatusCheck} (identical for every format). */
    private String checkStatus(final Map<String, Object> payload, final List<X509Certificate> issuerChain,
            final VerificationContext ctx) {
        if (!payload.containsKey("status")) {
            return StatusCheck.absent(ctx.statusPolicy(), "credential has no status claim");
        }
        final StatusReference ref = statusReference(payload);
        if (ref == null) {
            return StatusCheck.notEvaluable(ctx.statusPolicy(), "credential status mechanism cannot be evaluated");
        }
        return StatusCheck.evaluate(status, ref, ctx.anchors(), new CredentialIssuer(issuerChain, null),
                ctx.statusPolicy());
    }

    /** True when {@code value} holds an {@code _sd} member or a {@code "..."} array digest at any depth. */
    private static boolean containsDigests(final Object value) {
        if (value instanceof Map<?, ?> map) {
            if (map.containsKey("_sd") || map.containsKey("...")) {
                return true;
            }
            return map.values().stream().anyMatch(SdJwtVcPresentationVerifier::containsDigests);
        }
        return value instanceof List<?> list && list.stream().anyMatch(SdJwtVcPresentationVerifier::containsDigests);
    }

    /** {@code status.status_list} of a present {@code status} claim, or null when it has no status_list. */
    private static StatusReference statusReference(final Map<String, Object> payload) {
        if (!(payload.get("status") instanceof Map<?, ?> st)) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "status is not an object");
        }
        if (!st.containsKey("status_list")) {
            return null; // empty, or only another mechanism: not evaluable here
        }
        if (!(st.get("status_list") instanceof Map<?, ?> list)
                || !(list.get("idx") instanceof Long idx) || idx < 0 || idx > Integer.MAX_VALUE
                || !(list.get("uri") instanceof String uri) || uri.isBlank()) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "status.status_list is malformed");
        }
        return new StatusReference(idx.intValue(), uri);
    }

    // ------------------------------------------------------------------------------------------- JOSE helpers

    /** JOSE {@code typ} comparison: case-insensitive, optional {@code application/} prefix (RFC 7515 §4.1.9). */
    private static boolean typIs(final Object typ, final String expected) {
        if (!(typ instanceof String s)) {
            return false;
        }
        String t = s.toLowerCase(Locale.ROOT);
        if (t.startsWith("application/")) {
            t = t.substring("application/".length());
        }
        return t.equals(expected);
    }

    private static JWSAlgorithm allowedAlg(final Map<String, Object> header, final String what) {
        if (header.get("alg") instanceof String name) {
            final JWSAlgorithm alg = JWSAlgorithm.parse(name);
            if (ALLOWED_ALGS.contains(alg)) {
                return alg;
            }
        }
        throw fail(WalletErrorCode.ALGORITHM_NOT_ALLOWED, what + " alg is not allowed");
    }

    /** A verifier when {@code alg} fits {@code key} (its EC curve for ES*, RSA &ge; 2048 for PS*), else null. */
    private static JWSVerifier verifierFor(final PublicKey key, final JWSAlgorithm alg) {
        try {
            if (key instanceof ECPublicKey ec) {
                final ECDSAVerifier v = new ECDSAVerifier(ec);
                return v.supportedJWSAlgorithms().contains(alg) ? v : null;
            }
            if (key instanceof RSAPublicKey rsa && rsa.getModulus().bitLength() >= MIN_RSA_BITS
                    && RSA_PSS.contains(alg)) {
                return new RSASSAVerifier(rsa);
            }
        } catch (final JOSEException e) {
            return null;
        }
        return null;
    }

    private static List<X509Certificate> x5c(final Map<String, Object> header) {
        if (!(header.get("x5c") instanceof List<?> encoded) || encoded.isEmpty()) {
            throw fail(WalletErrorCode.ISSUER_UNTRUSTED, "Issuer-signed JWT has no x5c");
        }
        final List<X509Certificate> chain = new ArrayList<>(encoded.size());
        try {
            final CertificateFactory factory = CertificateFactory.getInstance("X.509");
            for (final Object e : encoded) {
                if (!(e instanceof String b64)) {
                    throw fail(WalletErrorCode.ISSUER_UNTRUSTED, "x5c entry is not a string");
                }
                // x5c is standard (not URL) base64 of DER (RFC 7515 §4.1.6)
                chain.add((X509Certificate) factory.generateCertificate(
                        new ByteArrayInputStream(Base64.getDecoder().decode(b64))));
            }
        } catch (final CertificateException | IllegalArgumentException | ClassCastException e) {
            throw fail(WalletErrorCode.ISSUER_UNTRUSTED, "x5c certificate cannot be parsed");
        }
        return chain;
    }

    private static Instant numericDate(final Object value, final WalletErrorCode code, final String name) {
        final long seconds;
        if (value instanceof Long l) {
            seconds = l;
        } else if (value instanceof Double d && Double.isFinite(d) && Math.abs(d) < MAX_EPOCH_SECONDS) {
            seconds = (long) Math.floor(d);
        } else {
            throw fail(code, name + " is not a NumericDate");
        }
        if (Math.abs(seconds) >= MAX_EPOCH_SECONDS) {
            throw fail(code, name + " is out of range");
        }
        return Instant.ofEpochSecond(seconds);
    }

    private static boolean constantTimeEquals(final String a, final String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private static WalletVerificationException fail(final WalletErrorCode code, final String safeDetail) {
        return new WalletVerificationException(code, safeDetail);
    }

    /**
     * A compact JWS whose header and payload were decoded with {@link StrictJson#MAPPER}; the signature is checked by Nimbus
     * over the exact received signing input.
     */
    private record Jws(String compact, Map<String, Object> header, Map<String, Object> payload) {

        static Jws decode(final String compact, final String what) {
            final String[] parts = compact.split("\\.", -1);
            if (parts.length != 3) {
                throw fail(WalletErrorCode.INVALID_RESPONSE, what + " is not a compact JWS");
            }
            final Map<String, Object> header = json(parts[0], what);
            if (header.containsKey("crit") || header.containsKey("b64")) {
                throw fail(WalletErrorCode.INVALID_RESPONSE, what + " uses an unsupported header parameter");
            }
            return new Jws(compact, header, json(parts[1], what));
        }

        boolean verify(final JWSVerifier verifier) {
            try {
                return JWSObject.parse(compact).verify(verifier);
            } catch (final ParseException e) {
                throw fail(WalletErrorCode.INVALID_RESPONSE, "JWS cannot be parsed");
            } catch (final JOSEException e) {
                return false;
            }
        }

        @SuppressWarnings("unchecked")
        private static Map<String, Object> json(final String segment, final String what) {
            try {
                final Object parsed = StrictJson.MAPPER.readValue(Base64.getUrlDecoder().decode(segment), Object.class);
                if (parsed instanceof Map<?, ?> map) {
                    return (Map<String, Object>) map;
                }
            } catch (final IOException | IllegalArgumentException e) {
                // fall through: duplicate member, malformed JSON or base64url
            }
            throw fail(WalletErrorCode.INVALID_RESPONSE, what + " is not a strict JSON object");
        }

        /** Redacted: the compact form carries PID data. */
        @Override
        public String toString() {
            return "Jws[redacted]";
        }
    }
}
