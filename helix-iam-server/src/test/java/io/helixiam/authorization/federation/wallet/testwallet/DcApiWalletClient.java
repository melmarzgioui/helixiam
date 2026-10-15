/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.testwallet;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.SignedJWT;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The wallet's side of OpenID4VP over the W3C Digital Credentials API (OpenID4VP 1.0 Appendix A), test only. What the
 * browser hands the wallet is {@code {protocol, data}} plus the page's origin (the platform supplies it; here the test
 * does). Checked independently of production code: a signed request ({@code openid4vp-v1-signed}, A.3.2.1) must be a
 * {@code typ=oauth-authz-req+jwt} JWS signed by its {@code x5c} leaf with an {@code x509_hash} client_id of that leaf,
 * and its {@code expected_origins} must contain the origin (A.2: the wallet "MUST return an error" otherwise); an
 * unsigned one ({@code openid4vp-v1-unsigned}, A.3.1) must carry no {@code client_id}. Neither may carry
 * {@code response_uri}, {@code redirect_uri} or {@code state}. The answer is the {@code data} object of the
 * {@code DigitalCredential}: {@code {response: <JWE>}} for {@code dc_api.jwt}, {@code {vp_token}} for {@code dc_api}.
 */
public final class DcApiWalletClient {

    public static final String SIGNED = "openid4vp-v1-signed";
    public static final String UNSIGNED = "openid4vp-v1-unsigned";

    private static final Set<JWSAlgorithm> REQUEST_ALGS = Set.of(JWSAlgorithm.ES256, JWSAlgorithm.ES384,
            JWSAlgorithm.ES512);

    private DcApiWalletClient() {
    }

    /**
     * A DC API request the wallet accepted.
     *
     * @param protocol      the DC API protocol identifier
     * @param origin        the origin the platform reported (bare, no {@code origin:} prefix)
     * @param clientId      the request's client_id, or null (unsigned)
     * @param claims        the request parameters
     * @param encryptionKey the verifier's response-encryption key, or null
     * @param encValues     {@code encrypted_response_enc_values_supported} ({@code [A128GCM]} when absent)
     */
    public record DcApiRequest(String protocol, String origin, String clientId, Map<String, Object> claims,
            ECKey encryptionKey, List<String> encValues) {

        public String nonce() {
            return (String) claims.get("nonce");
        }

        public String responseMode() {
            return (String) claims.get("response_mode");
        }

        /** The SD-JWT KB-JWT audience over the DC API (A.4): {@code origin:<origin>}. */
        public String audience() {
            return "origin:" + origin;
        }

        /** The RFC 7638 thumbprint of the encryption key (the mdoc handover input), or null for {@code dc_api}. */
        public byte[] thumbprint() {
            try {
                return encryptionKey == null ? null : encryptionKey.toPublicJWK().computeThumbprint("SHA-256").decode();
            } catch (final JOSEException e) {
                throw new IllegalStateException(e);
            }
        }

        /** The OpenID4VPDCAPIHandover SessionTranscript (B.2.6.2), written with Jackson's CBOR writer. */
        public byte[] sessionTranscript() {
            final byte[] info = TestWallet.cbor(Arrays.asList(origin, nonce(), thumbprint()));
            return TestWallet.cbor(Arrays.asList(null, null,
                    List.of("OpenID4VPDCAPIHandover", TestWallet.sha("SHA-256", info))));
        }
    }

    /**
     * Verifies what {@code navigator.credentials.get} would hand the wallet for {@code origin}.
     *
     * @throws IllegalArgumentException naming the first check that failed ({@code expected_origins} included)
     */
    @SuppressWarnings("unchecked")
    public static DcApiRequest verify(final String protocol, final Map<String, Object> data, final String origin,
            final Instant now) {
        final Map<String, Object> claims;
        final String clientId;
        if (SIGNED.equals(protocol)) {
            if (data.size() != 1 || !(data.get("request") instanceof String jws)) {
                throw new IllegalArgumentException("a signed DC API request is {request: <JWS>} only");
            }
            claims = verifySigned(jws, now);
            clientId = (String) claims.get("client_id");
            if (!(claims.get("expected_origins") instanceof List<?> expected) || expected.isEmpty()) {
                throw new IllegalArgumentException("expected_origins is missing");
            }
            if (!expected.contains(origin)) {
                throw new IllegalArgumentException("invalid_request: the origin is not in expected_origins");
            }
        } else if (UNSIGNED.equals(protocol)) {
            claims = new LinkedHashMap<>(data);
            if (claims.containsKey("client_id") || claims.containsKey("request")) {
                throw new IllegalArgumentException("an unsigned DC API request carries no client_id or request");
            }
            clientId = null;
        } else {
            throw new IllegalArgumentException("unknown DC API protocol " + protocol);
        }
        for (final String forbidden : List.of("response_uri", "redirect_uri", "state", "request_uri")) {
            if (claims.containsKey(forbidden)) {
                throw new IllegalArgumentException(forbidden + " is not defined for the DC API");
            }
        }
        if (!"vp_token".equals(claims.get("response_type"))) {
            throw new IllegalArgumentException("response_type is not vp_token");
        }
        final Object mode = claims.get("response_mode");
        if (!"dc_api.jwt".equals(mode) && !"dc_api".equals(mode)) {
            throw new IllegalArgumentException("response_mode is not dc_api or dc_api.jwt");
        }
        if (!(claims.get("nonce") instanceof String nonce) || nonce.isBlank()) {
            throw new IllegalArgumentException("nonce is missing");
        }
        if (!(claims.get("dcql_query") instanceof Map<?, ?>)) {
            throw new IllegalArgumentException("dcql_query is missing");
        }
        final ECKey key = encryptionKey(claims);
        if ("dc_api.jwt".equals(mode) && key == null) {
            throw new IllegalArgumentException("dc_api.jwt without an encryption key");
        }
        return new DcApiRequest(protocol, origin, clientId, claims, key, encValues(claims));
    }

    /** The DigitalCredential {@code data} for {@code vpToken}: encrypted ({@code dc_api.jwt}) or plain. */
    public static Map<String, Object> respond(final DcApiRequest request, final Object vpToken) {
        if ("dc_api".equals(request.responseMode())) {
            return Map.of("vp_token", vpToken);
        }
        final EncryptionMethod enc = request.encValues().contains("A256GCM") ? EncryptionMethod.A256GCM
                : EncryptionMethod.parse(request.encValues().get(0));
        try {
            final JWEObject jwe = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, enc)
                    .keyID(request.encryptionKey().getKeyID()).build(),
                    new Payload(TestWallet.json(Map.of("vp_token", vpToken))));
            jwe.encrypt(new ECDHEncrypter(request.encryptionKey()));
            return Map.of("response", jwe.serialize());
        } catch (final JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Map<String, Object> verifySigned(final String jws, final Instant now) {
        try {
            final SignedJWT signed = SignedJWT.parse(jws);
            if (signed.getHeader().getType() == null
                    || !Oid4vpWalletClient.REQUEST_OBJECT_TYP.equals(signed.getHeader().getType().getType())) {
                throw new IllegalArgumentException("typ is not oauth-authz-req+jwt");
            }
            if (!REQUEST_ALGS.contains(signed.getHeader().getAlgorithm())) {
                throw new IllegalArgumentException("alg is not ES256/384/512");
            }
            if (signed.getHeader().getX509CertChain() == null || signed.getHeader().getX509CertChain().isEmpty()) {
                throw new IllegalArgumentException("x5c is missing");
            }
            final X509Certificate leaf = X509CertUtils.parse(signed.getHeader().getX509CertChain().get(0).decode());
            if (leaf == null || !(leaf.getPublicKey() instanceof ECPublicKey leafKey)
                    || !signed.verify(new ECDSAVerifier(leafKey))) {
                throw new IllegalArgumentException("signature does not verify with the x5c leaf");
            }
            final Map<String, Object> claims = signed.getJWTClaimsSet().getClaims();
            if (!(claims.get("client_id") instanceof String clientId)) {
                throw new IllegalArgumentException("a signed DC API request must carry client_id");
            }
            if (clientId.startsWith("x509_hash:")) {
                final String expected = TestWallet.b64url(TestWallet.sha("SHA-256", leaf.getEncoded()));
                if (!clientId.equals("x509_hash:" + expected)) {
                    throw new IllegalArgumentException("x509_hash does not match the x5c leaf");
                }
            } else if (!clientId.startsWith("x509_san_dns:")) {
                throw new IllegalArgumentException("unsupported client_id prefix");
            }
            final Date exp = signed.getJWTClaimsSet().getExpirationTime();
            if (exp != null && !now.isBefore(exp.toInstant())) {
                throw new IllegalArgumentException("request object is expired");
            }
            return claims;
        } catch (final ParseException | JOSEException | CertificateEncodingException e) {
            throw new IllegalArgumentException("request object could not be parsed or verified", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static ECKey encryptionKey(final Map<String, Object> claims) {
        if (!(claims.get("client_metadata") instanceof Map<?, ?> metadata) || metadata.get("jwks") == null) {
            return null;
        }
        try {
            final JWKSet set = JWKSet.parse((Map<String, Object>) metadata.get("jwks"));
            for (final JWK key : set.getKeys()) {
                if (key.isPrivate()) {
                    throw new IllegalArgumentException("client_metadata.jwks carries a private key");
                }
            }
            if (set.getKeys().size() != 1 || !(set.getKeys().get(0) instanceof ECKey ec) || ec.getKeyID() == null) {
                throw new IllegalArgumentException("client_metadata.jwks must hold exactly one EC key with a kid");
            }
            return ec;
        } catch (final ParseException e) {
            throw new IllegalArgumentException("client_metadata.jwks is not a JWK set", e);
        }
    }

    private static List<String> encValues(final Map<String, Object> claims) {
        if (claims.get("client_metadata") instanceof Map<?, ?> metadata
                && metadata.get("encrypted_response_enc_values_supported") instanceof List<?> values) {
            return values.stream().map(Object::toString).toList();
        }
        return List.of("A128GCM");
    }
}
