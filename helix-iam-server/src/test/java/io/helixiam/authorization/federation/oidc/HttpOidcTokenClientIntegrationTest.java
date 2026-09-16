/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.oidc;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Helix IAM E5.2: live validation of {@link HttpOidcTokenClient} against a real mock OIDC issuer
 * (JDK HttpServer serving /token + /jwks) with a Nimbus-signed ID token. Proves the genuine token
 * exchange + JWKS-signature + issuer/audience validation — including that a token signed by an
 * unknown key or carrying a wrong issuer is rejected. Fully offline (no external IdP).
 */
class HttpOidcTokenClientIntegrationTest {

    private static final String ISSUER = "https://issuer.test";
    private static final String CLIENT_ID = "client-1";

    private static HttpServer server;
    private static RSAKey signingKey;          // in the JWKS
    private static RSAKey foreignKey;           // NOT in the JWKS
    private static final AtomicReference<String> NEXT_ID_TOKEN = new AtomicReference<>();
    private static OidcProviderConfig config;

    private final HttpOidcTokenClient client = new HttpOidcTokenClient();

    @BeforeAll
    static void startIssuer() throws Exception {
        signingKey = new RSAKeyGenerator(2048).keyID("k1").generate();
        foreignKey = new RSAKeyGenerator(2048).keyID("k1").generate(); // same kid, different key
        final String jwks = new JWKSet(signingKey.toPublicJWK()).toString();

        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/token", ex -> respond(ex,
                "{\"id_token\":\"" + NEXT_ID_TOKEN.get() + "\",\"access_token\":\"at-123\",\"token_type\":\"Bearer\"}"));
        server.createContext("/jwks", ex -> respond(ex, jwks));
        server.start();

        final String base = "http://localhost:" + server.getAddress().getPort();
        config = new OidcProviderConfig("acme", "ACME", CLIENT_ID, "secret",
                base + "/authorize", base + "/token", base + "/jwks", ISSUER, List.of("openid", "email"));
    }

    @AfterAll
    static void stopIssuer() {
        if (server != null) {
            server.stop(0);
        }
    }

    private static void respond(final com.sun.net.httpserver.HttpExchange ex, final String body) throws java.io.IOException {
        final byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(200, bytes.length);
        ex.getResponseBody().write(bytes);
        ex.close();
    }

    private static String signedIdToken(final RSAKey key, final String issuer) throws Exception {
        final JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(CLIENT_ID)
                .subject("ext-1")
                .claim("email", "ada@acme.test")
                .claim("email_verified", true)
                .claim("nonce", "n-1")
                .expirationTime(new Date(System.currentTimeMillis() + 3_600_000))
                .build();
        final SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("k1").build(), claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    @Test
    void exchangesAndValidatesAGenuineSignedIdToken() throws Exception {
        NEXT_ID_TOKEN.set(signedIdToken(signingKey, ISSUER));

        final OidcTokenClient.OidcTokens tokens = client.exchange(config, "auth-code", "https://helix/cb");

        assertThat(tokens.idTokenClaims()).containsEntry("sub", "ext-1").containsEntry("email", "ada@acme.test");
        assertThat(tokens.accessToken()).isEqualTo("at-123");
    }

    @Test
    void rejectsAnIdTokenSignedByAnUnknownKey() throws Exception {
        NEXT_ID_TOKEN.set(signedIdToken(foreignKey, ISSUER)); // signature won't verify against the JWKS

        assertThatThrownBy(() -> client.exchange(config, "auth-code", "https://helix/cb"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void rejectsAnIdTokenWithTheWrongIssuer() throws Exception {
        NEXT_ID_TOKEN.set(signedIdToken(signingKey, "https://evil.test"));

        assertThatThrownBy(() -> client.exchange(config, "auth-code", "https://helix/cb"))
                .isInstanceOf(IllegalStateException.class);
    }
}
