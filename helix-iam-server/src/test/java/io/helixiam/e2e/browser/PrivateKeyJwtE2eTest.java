/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import io.helixiam.e2e.AbstractE2eTest;
import io.helixiam.e2e.E2eHttp;
import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * private_key_jwt end to end at the token endpoint: the client's registered JWKS is fetched through the outbound guard
 * (the harness allows only its own listener), so a client whose JWKS URL the guard refuses never makes the server
 * connect, and a valid assertion still gets a token.
 */
class PrivateKeyJwtE2eTest extends AbstractE2eTest {

    private static HttpServer allowed;
    private static HttpServer refused;
    private static final AtomicInteger REFUSED_HITS = new AtomicInteger();
    private static RSAKey key;

    @BeforeAll
    static void servers() throws Exception {
        key = new RSAKeyGenerator(2048).keyID("pkj-1").generate();
        final byte[] jwks = new JWKSet(key.toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8);
        allowed = HttpServer.create(new InetSocketAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), 0), 0);
        allowed.createContext("/jwks", ex -> {
            try (ex) {
                ex.getResponseHeaders().add("Content-Type", "application/json");
                ex.sendResponseHeaders(200, jwks.length);
                try (OutputStream out = ex.getResponseBody()) {
                    out.write(jwks);
                }
            }
        });
        allowed.start();
        HarnessEgressGuard.allow(allowed.getAddress().getPort());
        refused = HttpServer.create(new InetSocketAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), 0), 0);
        refused.createContext("/", ex -> {
            REFUSED_HITS.incrementAndGet();
            try (ex) {
                ex.sendResponseHeaders(200, jwks.length);
                try (OutputStream out = ex.getResponseBody()) {
                    out.write(jwks);
                }
            }
        });
        refused.start();
    }

    @AfterAll
    static void stop() {
        HarnessEgressGuard.revoke(allowed.getAddress().getPort());
        allowed.stop(0);
        refused.stop(0);
    }

    private String client(final String realm, final String jwksUrl) {
        final String clientId = E2eSeed.unique("pkj");
        final E2eHttp.Response created = adminSession().post("/admin/realms/" + realm + "/clients", Map.of(
                "clientId", clientId, "grantTypes", List.of("client_credentials"),
                "tokenEndpointAuthMethod", "PRIVATE_KEY_JWT", "jwksUrl", jwksUrl));
        assertThat(created.status()).as(created.toString()).isEqualTo(201);
        return clientId;
    }

    private E2eHttp.Response token(final String realm, final String clientId) throws Exception {
        final String aud = oidc(realm).issuer() + "/oauth2/token";
        final SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("pkj-1").build(),
                new JWTClaimsSet.Builder().issuer(clientId).subject(clientId).audience(aud)
                        .jwtID(UUID.randomUUID().toString()).issueTime(new Date())
                        .expirationTime(new Date(System.currentTimeMillis() + 60_000)).build());
        jwt.sign(new RSASSASigner(key));
        return newBrowser().postForm(oidc(realm).realmPath() + "/oauth2/token", Map.of(
                "grant_type", "client_credentials", "client_id", clientId,
                "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion", jwt.serialize()));
    }

    @Test
    void aValidAssertionGetsAToken() throws Exception {
        final String realm = E2eSeed.unique("pkj");
        seed().realm(realm);
        final String clientId = client(realm, "http://127.0.0.1:" + allowed.getAddress().getPort() + "/jwks");

        final E2eHttp.Response r = token(realm, clientId);

        assertThat(r.status()).as(r.toString()).isEqualTo(200);
        assertThat(r.json().path("access_token").asText()).isNotBlank();
    }

    @Test
    void aJwksUrlTheGuardRefusesIsNeverFetched() throws Exception {
        final String realm = E2eSeed.unique("pkj");
        seed().realm(realm);
        final String clientId = client(realm, "http://127.0.0.1:" + refused.getAddress().getPort() + "/jwks");

        final E2eHttp.Response r = token(realm, clientId);

        assertThat(r.status()).as(r.toString()).isEqualTo(401);
        assertThat(REFUSED_HITS).hasValue(0);
    }
}
