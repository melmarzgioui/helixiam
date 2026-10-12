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
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.SignedJWT;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/**
 * The wallet's OpenID4VP protocol side, test only: reads an invocation URL, fetches and verifies the signed request
 * object (typ, x5c leaf signature, client_id identity and binding, aud, exp), and answers with a
 * {@code direct_post.jwt} JWE to the request's encryption key. Values are checked here independently of production
 * code. The x5c chain is not validated against a trust anchor.
 */
public final class Oid4vpWalletClient {

    private Oid4vpWalletClient() {
    }

    /** OpenID4VP 1.0 §5: the only request-object {@code typ} a wallet may process. */
    public static final String REQUEST_OBJECT_TYP = "oauth-authz-req+jwt";
    /** OpenID4VP 1.0 §5.8: the request-object {@code aud} under static discovery. */
    public static final String STATIC_DISCOVERY_AUD = "https://self-issued.me/v2";

    private static final Set<JWSAlgorithm> REQUEST_ALGS = Set.of(JWSAlgorithm.ES256, JWSAlgorithm.ES384,
            JWSAlgorithm.ES512);

    /**
     * A request object the wallet fetched and accepted.
     *
     * @param clientId      the {@code client_id} (identical in the invocation URL and the request object)
     * @param requestUri    the {@code request_uri} the object was fetched from
     * @param header        the verified JWS header
     * @param claims        the request-object claims
     * @param encryptionKey the verifier's public response-encryption key from {@code client_metadata.jwks}, or null
     *                      when the request carries none
     * @param encValues     {@code encrypted_response_enc_values_supported} ({@code [A128GCM]} when absent, §8.3)
     */
    public record VerifiedRequest(String clientId, String requestUri, JWSHeader header, Map<String, Object> claims,
            ECKey encryptionKey, List<String> encValues) {

        public String claim(final String name) {
            final Object value = claims.get(name);
            return value == null ? null : value.toString();
        }

        public String responseUri() {
            return claim("response_uri");
        }

        public String responseMode() {
            return claim("response_mode");
        }

        public String nonce() {
            return claim("nonce");
        }

        public String state() {
            return claim("state");
        }
    }

    /**
     * What a wallet does with an invocation URL: reads {@code client_id} and {@code request_uri}, fetches the request
     * object with {@code fetch} (given the decoded {@code request_uri}), and verifies it with
     * {@link #verifyRequest}.
     */
    public static VerifiedRequest fetchAndVerifyRequest(final String invocationUrl,
            final Function<String, String> fetch, final Instant now) {
        final Map<String, String> params = invocationParameters(invocationUrl);
        final String requestUri = params.get("request_uri");
        if (requestUri == null || params.get("client_id") == null) {
            throw new IllegalArgumentException("invocation URL lacks client_id or request_uri");
        }
        return verifyRequest(params.get("client_id"), requestUri, fetch.apply(requestUri), now);
    }

    /**
     * Verifies a request object the way a HAIP wallet must (OpenID4VP 1.0 §5, §5.8, §5.9.3, §5.10.1): {@code typ},
     * an ECDSA signature by the {@code x5c} leaf, the {@code client_id} claim equal to the invocation's one and bound
     * to the leaf ({@code x509_hash}: SHA-256 of its DER; {@code x509_san_dns}: a dNSName SAN, with the
     * {@code response_uri} FQDN equal to it), {@code aud}, an unexpired {@code exp}, and only public keys in
     * {@code client_metadata.jwks}. The certificate chain is not validated against a trust anchor here.
     *
     * @throws IllegalArgumentException naming the first check that failed
     */
    public static VerifiedRequest verifyRequest(final String clientIdParam, final String requestUri, final String jwt,
            final Instant now) {
        try {
            final SignedJWT signed = SignedJWT.parse(jwt);
            final JWSHeader header = signed.getHeader();
            if (header.getType() == null || !REQUEST_OBJECT_TYP.equals(header.getType().getType())) {
                throw new IllegalArgumentException("typ is not " + REQUEST_OBJECT_TYP);
            }
            if (!REQUEST_ALGS.contains(header.getAlgorithm())) {
                throw new IllegalArgumentException("alg is not ES256/384/512");
            }
            if (header.getX509CertChain() == null || header.getX509CertChain().isEmpty()) {
                throw new IllegalArgumentException("x5c is missing");
            }
            final X509Certificate leaf = X509CertUtils.parse(
                    header.getX509CertChain().get(0).decode());
            if (leaf == null || !(leaf.getPublicKey() instanceof ECPublicKey leafKey)) {
                throw new IllegalArgumentException("x5c leaf is not an EC certificate");
            }
            if (!signed.verify(new ECDSAVerifier(leafKey))) {
                throw new IllegalArgumentException("signature does not verify with the x5c leaf");
            }
            final Map<String, Object> claims = signed.getJWTClaimsSet().getClaims();
            final Object clientId = claims.get("client_id");
            if (!(clientId instanceof String id) || !id.equals(clientIdParam)) {
                throw new IllegalArgumentException("client_id claim differs from the invocation client_id");
            }
            checkClientIdBinding(id, leaf, (String) claims.get("response_uri"));
            if (!List.of(STATIC_DISCOVERY_AUD).equals(signed.getJWTClaimsSet().getAudience())) {
                throw new IllegalArgumentException("aud is not " + STATIC_DISCOVERY_AUD);
            }
            final Date exp = signed.getJWTClaimsSet().getExpirationTime();
            if (exp == null || !now.isBefore(exp.toInstant())) {
                throw new IllegalArgumentException("request object is expired or has no exp");
            }
            if (!"vp_token".equals(claims.get("response_type"))) {
                throw new IllegalArgumentException("response_type is not vp_token");
            }
            return new VerifiedRequest(id, requestUri, header, claims, encryptionKey(claims),
                    encValues(claims));
        } catch (final ParseException | JOSEException e) {
            throw new IllegalArgumentException("request object could not be parsed or verified", e);
        }
    }

    /**
     * The {@code direct_post.jwt} response body a wallet POSTs (OpenID4VP 1.0 §8.3, HAIP §5): a JWE with
     * {@code alg=ECDH-ES} to the request's encryption key, its {@code kid} in the header, {@code enc} A256GCM when
     * offered (HAIP "SHOULD") else the first offered value, wrapping {@code {vp_token, state}}.
     */
    public static String respond(final VerifiedRequest request, final Object vpToken) {
        if (!"direct_post.jwt".equals(request.responseMode()) || request.encryptionKey() == null) {
            throw new IllegalArgumentException("request does not ask for an encrypted (direct_post.jwt) response");
        }
        final EncryptionMethod enc = request.encValues().contains("A256GCM")
                ? EncryptionMethod.A256GCM
                : EncryptionMethod.parse(request.encValues().get(0));
        final Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("vp_token", vpToken);
        payload.put("state", request.state());
        try {
            final JWEObject jwe = new JWEObject(
                    new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, enc)
                            .keyID(request.encryptionKey().getKeyID()).build(),
                    new Payload(TestWallet.json(payload)));
            jwe.encrypt(new ECDHEncrypter(request.encryptionKey()));
            return jwe.serialize();
        } catch (final JOSEException e) {
            throw new IllegalStateException("Could not encrypt the test response", e);
        }
    }

    /**
     * The query parameters of a {@code <scheme>://?...} invocation URL, strictly percent-decoded (RFC 3986): a
     * {@code +} is refused rather than read as a space, because the verifier must not form-encode.
     */
    public static Map<String, String> invocationParameters(final String invocationUrl) {
        final int q = invocationUrl.indexOf('?');
        if (q < 0) {
            throw new IllegalArgumentException("invocation URL has no query");
        }
        final Map<String, String> params = new LinkedHashMap<>();
        for (final String pair : invocationUrl.substring(q + 1).split("&")) {
            final int eq = pair.indexOf('=');
            if (eq <= 0 || params.put(pctDecode(pair.substring(0, eq)), pctDecode(pair.substring(eq + 1))) != null) {
                throw new IllegalArgumentException("malformed or repeated invocation parameter");
            }
        }
        return params;
    }

    /**
     * RFC 3986 percent-decoding (UTF-8). Refuses {@code +}, any character outside the unreserved set, and a malformed
     * escape (a {@code %} not followed by exactly two hex digits) with an {@link IllegalArgumentException}.
     */
    public static String pctDecode(final String encoded) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i < encoded.length(); i++) {
            final char c = encoded.charAt(i);
            if (c == '%') {
                if (i + 3 > encoded.length()) {
                    throw new IllegalArgumentException("truncated percent escape");
                }
                final int hi = hexDigit(encoded.charAt(i + 1));
                final int lo = hexDigit(encoded.charAt(i + 2));
                if (hi < 0 || lo < 0) {
                    throw new IllegalArgumentException("percent escape is not two hex digits");
                }
                out.write(hi << 4 | lo);
                i += 2;
            } else if (Character.isLetterOrDigit(c) && c < 128 || "-._~".indexOf(c) >= 0) {
                out.write(c);
            } else {
                throw new IllegalArgumentException("unencoded reserved character '" + c + "'");
            }
        }
        return out.toString(StandardCharsets.UTF_8);
    }

    /** An ASCII hex digit's value, or -1 (Character.digit would also accept non-ASCII digits). */
    private static int hexDigit(final char c) {
        return c < 128 ? Character.digit(c, 16) : -1;
    }

    private static void checkClientIdBinding(final String clientId, final X509Certificate leaf,
            final String responseUri) {
        try {
            if (clientId.startsWith("x509_hash:")) {
                final String expected = TestWallet.b64url(TestWallet.sha("SHA-256", leaf.getEncoded()));
                if (!clientId.substring("x509_hash:".length()).equals(expected)) {
                    throw new IllegalArgumentException("x509_hash does not match the x5c leaf");
                }
            } else if (clientId.startsWith("x509_san_dns:")) {
                final String host = clientId.substring("x509_san_dns:".length());
                final boolean inSan = leaf.getSubjectAlternativeNames() != null
                        && leaf.getSubjectAlternativeNames().stream()
                        .anyMatch(san -> Integer.valueOf(2).equals(san.get(0)) && host.equals(san.get(1)));
                if (!inSan) {
                    throw new IllegalArgumentException("x509_san_dns host is not a dNSName SAN of the x5c leaf");
                }
                if (responseUri == null || !host.equalsIgnoreCase(URI.create(responseUri).getHost())) {
                    throw new IllegalArgumentException("response_uri FQDN does not match x509_san_dns");
                }
            } else {
                throw new IllegalArgumentException("unsupported client_id prefix");
            }
        } catch (final CertificateException e) {
            throw new IllegalArgumentException("x5c leaf could not be read", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static ECKey encryptionKey(final Map<String, Object> claims) throws ParseException {
        if (!(claims.get("client_metadata") instanceof Map<?, ?> metadata) || metadata.get("jwks") == null) {
            return null;
        }
        final JWKSet set = JWKSet.parse(
                (Map<String, Object>) metadata.get("jwks"));
        for (final JWK key : set.getKeys()) {
            if (key.isPrivate()) {
                throw new IllegalArgumentException("client_metadata.jwks carries a private key");
            }
        }
        if (set.getKeys().size() != 1 || !(set.getKeys().get(0) instanceof ECKey ec) || ec.getKeyID() == null) {
            throw new IllegalArgumentException("client_metadata.jwks must hold exactly one EC key with a kid");
        }
        return ec;
    }

    private static List<String> encValues(final Map<String, Object> claims) {
        if (claims.get("client_metadata") instanceof Map<?, ?> metadata
                && metadata.get("encrypted_response_enc_values_supported") instanceof List<?> values) {
            return values.stream().map(Object::toString).toList();
        }
        return List.of("A128GCM");
    }
}
