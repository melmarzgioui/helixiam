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
import io.helixiam.testsupport.RebindingTarget;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** M6: the OIDC broker's token exchange and JWKS fetch go to the addresses the guard validated. */
class HttpOidcTokenClientRebindingTest {

    @Test
    void theTokenEndpointAndTheJwksAreFetchedFromTheValidatedAddressesOnly() throws Exception {
        final RSAKey key = new RSAKeyGenerator(2048).keyID("k1").generate();
        final JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer("https://issuer.test").audience("client-1")
                .subject("ext-1").expirationTime(new Date(System.currentTimeMillis() + 3_600_000)).build();
        final SignedJWT idToken = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("k1").build(), claims);
        idToken.sign(new RSASSASigner(key));
        try (RebindingTarget token = RebindingTarget.http("token.rebind.test");
             RebindingTarget jwks = RebindingTarget.http("jwks.rebind.test")) {
            token.respond(s -> new RebindingTarget.Answer(200, "application/json",
                    "{\"id_token\":\"" + idToken.serialize() + "\",\"access_token\":\"at-1\"}"));
            jwks.respond(s -> new RebindingTarget.Answer(200, "application/json",
                    new JWKSet(key.toPublicJWK()).toString()));
            final OidcProviderConfig config = new OidcProviderConfig("acme", "ACME", "client-1", "secret",
                    token.url("http", "/authorize"), token.url("http", "/token"), jwks.url("http", "/jwks"),
                    "https://issuer.test", List.of("openid"));

            final OidcTokenClient.OidcTokens tokens = new HttpOidcTokenClient(RebindingTarget.guard(token, jwks))
                    .exchange(config, "code-1", "https://helix/cb");

            assertThat(tokens.idTokenClaims()).containsEntry("sub", "ext-1");
            assertThat(token.requests()).hasSize(1);
            assertThat(token.requests().get(0).method()).isEqualTo("POST");
            assertThat(token.requests().get(0).body()).contains("grant_type=authorization_code").contains("code=code-1");
            assertThat(jwks.requests()).hasSize(1);
            assertThat(token.lookups()).isEqualTo(1);
            assertThat(jwks.lookups()).isEqualTo(1);
        }
    }

    @Test
    void theBrokerCachesTheProvidersJwksAcrossLogins() throws Exception {
        final RSAKey key = new RSAKeyGenerator(2048).keyID("k1").generate();
        final JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer("https://issuer.test").audience("client-1")
                .subject("ext-1").expirationTime(new Date(System.currentTimeMillis() + 3_600_000)).build();
        final SignedJWT idToken = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("k1").build(), claims);
        idToken.sign(new RSASSASigner(key));
        try (RebindingTarget op = RebindingTarget.http("op.cache.test")) {
            op.respond(s -> s.path().equals("/jwks")
                    ? new RebindingTarget.Answer(200, "application/json", new JWKSet(key.toPublicJWK()).toString())
                    : new RebindingTarget.Answer(200, "application/json",
                    "{\"id_token\":\"" + idToken.serialize() + "\",\"access_token\":\"at\"}"));
            final io.helixiam.common.net.OutboundUrlGuard guard = new io.helixiam.common.net.OutboundUrlGuard(false,
                    List.of("op.cache.test:" + op.port()), host -> new java.net.InetAddress[] {
                            java.net.InetAddress.getByAddress(host, new byte[] {127, 0, 0, 1})});
            final OidcProviderConfig config = new OidcProviderConfig("acme", "ACME", "client-1", "secret",
                    op.url("http", "/authorize"), op.url("http", "/token"), op.url("http", "/jwks"),
                    "https://issuer.test", List.of("openid"));
            final HttpOidcTokenClient client = new HttpOidcTokenClient(guard);

            for (int i = 0; i < 3; i++) {
                client.exchange(config, "code-" + i, "https://helix/cb");
            }

            assertThat(op.requests().stream().filter(s -> s.path().equals("/jwks")).count()).isEqualTo(1);
        }
    }
}
