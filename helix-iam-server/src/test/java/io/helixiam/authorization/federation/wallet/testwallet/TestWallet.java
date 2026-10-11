/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.testwallet;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import io.helixiam.authorization.federation.wallet.status.StatusReference;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki.Leaf;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * A test-only issuer and holder wallet: issues SD-JWT VC PIDs (every top-level claim selectively disclosable, flat)
 * signed by a {@link TestPki} leaf with an {@code x5c} header, and presents them with a Key Binding JWT. Digests are
 * computed here independently of production code. Immutable; {@code with*} returns a changed copy, so a negative test
 * changes exactly one thing.
 *
 * <pre>{@code
 * TestWallet wallet = TestWallet.create();
 * TestWallet.SdJwtCredential pid = wallet.sdJwtPid(Map.of("given_name", "Erika"), iat, exp, Optional.empty());
 * String vpToken = wallet.present(pid, Set.of("given_name"), "x509_san_dns:verifier.example", nonce);
 * }</pre>
 */
public final class TestWallet {

    public static final String PID_VCT = "urn:eudi:pid:1";
    public static final String ISSUER = "https://pid-issuer.example";

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();

    private final TestPki pki;
    private final Leaf issuer;
    private final JWSAlgorithm alg;
    private final String typ;
    private final String vct;
    private final String sdAlg;
    private final JWK holderKey;
    private final boolean includeCnf;
    private final boolean includeX5c;
    private final Map<String, Object> extraPayload;

    private TestWallet(final TestPki pki, final Leaf issuer, final JWSAlgorithm alg, final String typ,
            final String vct, final String sdAlg, final JWK holderKey, final boolean includeCnf,
            final boolean includeX5c, final Map<String, Object> extraPayload) {
        this.pki = pki;
        this.issuer = issuer;
        this.alg = alg;
        this.typ = typ;
        this.vct = vct;
        this.sdAlg = sdAlg;
        this.holderKey = holderKey;
        this.includeCnf = includeCnf;
        this.includeX5c = includeX5c;
        this.extraPayload = Collections.unmodifiableMap(new LinkedHashMap<>(extraPayload));
    }

    /** A new PKI, an EC P-256 issuer leaf (ES256), typ {@code dc+sd-jwt}, {@code sha-256}, an EC P-256 holder key. */
    public static TestWallet create() {
        final TestPki pki = TestPki.create();
        return new TestWallet(pki, pki.issueLeaf(TestPki.LeafSpec.defaults()), JWSAlgorithm.ES256, "dc+sd-jwt",
                PID_VCT, "sha-256", ecKey(Curve.P_256), true, true, Map.of("iss", ISSUER));
    }

    /** A fresh EC holder key on {@code curve}. */
    public static ECKey ecKey(final Curve curve) {
        try {
            return new ECKeyGenerator(curve).generate();
        } catch (final JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    public TestPki pki() {
        return pki;
    }

    public Leaf issuer() {
        return issuer;
    }

    public JWK holderKey() {
        return holderKey;
    }

    /** Issuer leaf and the JWS {@code alg} it signs with (no consistency check: tests use mismatches). */
    public TestWallet withIssuer(final Leaf leaf, final JWSAlgorithm signingAlg) {
        return new TestWallet(pki, leaf, signingAlg, typ, vct, sdAlg, holderKey, includeCnf, includeX5c, extraPayload);
    }

    public TestWallet withTyp(final String value) {
        return new TestWallet(pki, issuer, alg, value, vct, sdAlg, holderKey, includeCnf, includeX5c, extraPayload);
    }

    public TestWallet withVct(final String value) {
        return new TestWallet(pki, issuer, alg, typ, value, sdAlg, holderKey, includeCnf, includeX5c, extraPayload);
    }

    public TestWallet withSdAlg(final String value) {
        return new TestWallet(pki, issuer, alg, typ, vct, value, holderKey, includeCnf, includeX5c, extraPayload);
    }

    public TestWallet withHolderKey(final JWK value) {
        return new TestWallet(pki, issuer, alg, typ, vct, sdAlg, value, includeCnf, includeX5c, extraPayload);
    }

    /** Leave {@code cnf} out of the issuer payload (a credential that cannot be holder-bound). */
    public TestWallet withoutCnf() {
        return new TestWallet(pki, issuer, alg, typ, vct, sdAlg, holderKey, false, includeX5c, extraPayload);
    }

    public TestWallet withoutX5c() {
        return new TestWallet(pki, issuer, alg, typ, vct, sdAlg, holderKey, includeCnf, false, extraPayload);
    }

    /** Sets (or, with {@code null}, removes) a plain, always-disclosed issuer payload member such as iss or nbf. */
    public TestWallet withPayloadClaim(final String name, final Object value) {
        final Map<String, Object> extra = new LinkedHashMap<>(extraPayload);
        if (value == null) {
            extra.remove(name);
        } else {
            extra.put(name, value);
        }
        return new TestWallet(pki, issuer, alg, typ, vct, sdAlg, holderKey, includeCnf, includeX5c, extra);
    }

    /** An issued SD-JWT VC: the Issuer-signed JWT, one disclosure per claim name, and the holder's private key. */
    public record SdJwtCredential(String issuerJwt, Map<String, String> disclosures, JWK holderKey) {

        /** Same disclosures and holder, a different Issuer-signed JWT (tampering tests). */
        public SdJwtCredential withIssuerJwt(final String value) {
            return new SdJwtCredential(value, disclosures, holderKey);
        }
    }

    /**
     * A PID: {@code claims} are each selectively disclosable (one flat disclosure per top-level member, plus a decoy);
     * {@code vct}, {@code iat}, {@code exp}, {@code status}, {@code cnf}, {@code _sd_alg} and the extra payload claims
     * are plain. {@code iat} / {@code exp} may be {@code null} (omitted).
     */
    public SdJwtCredential sdJwtPid(final Map<String, Object> claims, final Instant iat, final Instant exp,
            final Optional<StatusReference> status) {
        final Map<String, String> disclosures = new LinkedHashMap<>();
        final List<String> digests = new ArrayList<>();
        for (final Map.Entry<String, Object> claim : claims.entrySet()) {
            final String disclosure = disclosure(claim.getKey(), claim.getValue());
            disclosures.put(claim.getKey(), disclosure);
            digests.add(digest(disclosure, sdAlg));
        }
        digests.add(digest(disclosure("decoy", "decoy"), sdAlg)); // never presented
        Collections.sort(digests);

        final Map<String, Object> payload = new LinkedHashMap<>(extraPayload);
        if (vct != null) {
            payload.put("vct", vct);
        }
        if (iat != null) {
            payload.put("iat", iat.getEpochSecond());
        }
        if (exp != null) {
            payload.put("exp", exp.getEpochSecond());
        }
        payload.put("_sd_alg", sdAlg);
        payload.put("_sd", digests);
        if (includeCnf) {
            payload.put("cnf", Map.of("jwk", holderKey.toPublicJWK().toJSONObject()));
        }
        status.ifPresent(s -> payload.put("status",
                Map.of("status_list", Map.of("idx", s.idx(), "uri", s.uri()))));
        return new SdJwtCredential(signIssuerJwt(json(payload)), disclosures, holderKey);
    }

    /** Signs {@code rawPayloadJson} byte-exact (so a test can repeat a key) with this wallet's issuer header. */
    public String signIssuerJwt(final String rawPayloadJson) {
        final JWSHeader.Builder header = new JWSHeader.Builder(alg);
        if (typ != null) {
            header.type(new JOSEObjectType(typ));
        }
        if (includeX5c) {
            final List<Base64> x5c = new ArrayList<>();
            for (final X509Certificate cert : issuer.chain()) {
                try {
                    x5c.add(Base64.encode(cert.getEncoded()));
                } catch (final Exception e) {
                    throw new IllegalStateException(e);
                }
            }
            header.x509CertChain(x5c);
        }
        return sign(header.build(), rawPayloadJson, signer(issuer.privateKey()));
    }

    // ------------------------------------------------------------------------------------------- presentation

    /** The holder's KB-JWT parameters; {@link #of} gives a valid one, {@code with*} breaks exactly one thing. */
    public record KeyBinding(String typ, Object aud, String nonce, Instant iat, JWK signingKey, JWSAlgorithm alg,
            String sdHash, String sdHashAlg, String rawPayloadJson) {

        /** typ {@code kb+jwt}, iat now, signed with the credential's holder key, correct sd_hash. */
        public static KeyBinding of(final String aud, final String nonce) {
            return new KeyBinding("kb+jwt", aud, nonce, Instant.now(), null, null, null, null, null);
        }

        public KeyBinding withTyp(final String value) {
            return new KeyBinding(value, aud, nonce, iat, signingKey, alg, sdHash, sdHashAlg, rawPayloadJson);
        }

        /** A string or a JSON array (list). */
        public KeyBinding withAud(final Object value) {
            return new KeyBinding(typ, value, nonce, iat, signingKey, alg, sdHash, sdHashAlg, rawPayloadJson);
        }

        public KeyBinding withIat(final Instant value) {
            return new KeyBinding(typ, aud, nonce, value, signingKey, alg, sdHash, sdHashAlg, rawPayloadJson);
        }

        /** Sign with another key (and its default alg unless {@link #withAlg} is also given). */
        public KeyBinding withSigningKey(final JWK value) {
            return new KeyBinding(typ, aud, nonce, iat, value, alg, sdHash, sdHashAlg, rawPayloadJson);
        }

        public KeyBinding withAlg(final JWSAlgorithm value) {
            return new KeyBinding(typ, aud, nonce, iat, signingKey, value, sdHash, sdHashAlg, rawPayloadJson);
        }

        /** A fixed sd_hash value instead of the computed one. */
        public KeyBinding withSdHash(final String value) {
            return new KeyBinding(typ, aud, nonce, iat, signingKey, alg, value, sdHashAlg, rawPayloadJson);
        }

        /** Compute sd_hash with this hash instead of the credential's {@code _sd_alg}. */
        public KeyBinding withSdHashAlg(final String value) {
            return new KeyBinding(typ, aud, nonce, iat, signingKey, alg, sdHash, value, rawPayloadJson);
        }

        /** Sign this payload JSON byte-exact; {@code %SD_HASH%} is replaced with the computed sd_hash. */
        public KeyBinding withRawPayload(final String value) {
            return new KeyBinding(typ, aud, nonce, iat, signingKey, alg, sdHash, sdHashAlg, value);
        }
    }

    /** {@code <issuer-jwt>~<disclosures of disclose>~<kb-jwt>} with a valid KB-JWT. */
    public String present(final SdJwtCredential credential, final Set<String> disclose, final String aud,
            final String nonce) {
        return present(credential, disclose, KeyBinding.of(aud, nonce));
    }

    public String present(final SdJwtCredential credential, final Set<String> disclose, final KeyBinding kb) {
        final String sdJwt = presentWithoutKeyBinding(credential, disclose);
        final String hash = kb.sdHash() != null ? kb.sdHash()
                : digest(sdJwt, kb.sdHashAlg() != null ? kb.sdHashAlg() : sdAlg);
        final String payload;
        if (kb.rawPayloadJson() != null) {
            payload = kb.rawPayloadJson().replace("%SD_HASH%", hash);
        } else {
            final Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("iat", kb.iat().getEpochSecond());
            claims.put("aud", kb.aud());
            claims.put("nonce", kb.nonce());
            claims.put("sd_hash", hash);
            payload = json(claims);
        }
        final JWK key = kb.signingKey() != null ? kb.signingKey() : credential.holderKey();
        final JWSAlgorithm signingAlg = kb.alg() != null ? kb.alg() : defaultAlg(key);
        final JWSHeader.Builder header = new JWSHeader.Builder(signingAlg);
        if (kb.typ() != null) {
            header.type(new JOSEObjectType(kb.typ()));
        }
        return sdJwt + sign(header.build(), payload, signer(key));
    }

    /** {@code <issuer-jwt>~<disclosures>~} (no KB-JWT). Unknown names in {@code disclose} fail the test. */
    public String presentWithoutKeyBinding(final SdJwtCredential credential, final Set<String> disclose) {
        final StringBuilder sb = new StringBuilder(credential.issuerJwt()).append('~');
        for (final String name : disclose) {
            final String d = credential.disclosures().get(name);
            if (d == null) {
                throw new IllegalArgumentException("no disclosure for " + name);
            }
            sb.append(d).append('~');
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------------------------------- helpers

    /** base64url(H(ASCII(input))) with an SD-JWT hash name (sha-256/384/512); independent of production code. */
    public static String digest(final String input, final String sdHashName) {
        try {
            final String jca = switch (sdHashName) {
                case "sha-256" -> "SHA-256";
                case "sha-384" -> "SHA-384";
                case "sha-512" -> "SHA-512";
                default -> throw new IllegalArgumentException(sdHashName);
            };
            return b64url(MessageDigest.getInstance(jca).digest(input.getBytes(StandardCharsets.US_ASCII)));
        } catch (final java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String b64url(final byte[] bytes) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static String b64url(final String utf8) {
        return b64url(utf8.getBytes(StandardCharsets.UTF_8));
    }

    public static String json(final Object value) {
        try {
            return JSON.writeValueAsString(value);
        } catch (final JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String disclosure(final String name, final Object value) {
        final byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return b64url(json(List.of(b64url(salt), name, value)));
    }

    private static String sign(final JWSHeader header, final String payloadJson, final JWSSigner signer) {
        try {
            final JWSObject jws = new JWSObject(header, new Payload(payloadJson.getBytes(StandardCharsets.UTF_8)));
            jws.sign(signer);
            return jws.serialize();
        } catch (final JOSEException e) {
            throw new IllegalStateException("Could not sign the test JWT", e);
        }
    }

    private static JWSSigner signer(final PrivateKey key) {
        try {
            return key instanceof ECPrivateKey ec ? new ECDSASigner(ec) : new RSASSASigner(key);
        } catch (final JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static JWSSigner signer(final JWK key) {
        try {
            return key instanceof ECKey ec ? new ECDSASigner(ec) : new RSASSASigner(key.toRSAKey());
        } catch (final JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static JWSAlgorithm defaultAlg(final JWK key) {
        if (key instanceof ECKey ec) {
            final Curve curve = ec.getCurve();
            return Curve.P_384.equals(curve) ? JWSAlgorithm.ES384
                    : Curve.P_521.equals(curve) ? JWSAlgorithm.ES512 : JWSAlgorithm.ES256;
        }
        return JWSAlgorithm.PS256;
    }
}
