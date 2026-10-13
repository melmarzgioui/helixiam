/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.workloadidentity;

import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import io.helixiam.testsupport.RebindingTarget;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** M6: WIF issuer discovery and JWKS fetches go to the address the guard validated. */
class WorkloadIdentityRebindingTest {

    @Test
    void aJwksHostThatRebindsAfterTheUpFrontCheckIsNeverContacted() throws Exception {
        // jwkSource() checks the URI once up front (refusing internal URIs at once); every fetch behind the handle
        // resolves again through the guard and connects only to what that resolution validated. Here the up-front
        // check gets the validated answer and the fetch the metadata address: the fetch is refused, nothing connects.
        final String jwks = new JWKSet(new RSAKeyGenerator(2048).keyID("k1").generate().toPublicJWK()).toString();
        try (RebindingTarget target = RebindingTarget.http("wif.rebind.test")) {
            target.respond(s -> new RebindingTarget.Answer(200, "application/json", jwks));
            final var source = new WorkloadTokenVerifier(target.guard()).jwkSource(target.url("http", "/jwks"));

            assertThatThrownBy(() -> source.get(new JWKSelector(new JWKMatcher.Builder().build()), null))
                    .hasMessageContaining("SSRF");
            assertThat(target.requests()).isEmpty();
            assertThat(target.lookups()).isEqualTo(2);
        }
    }

    @Test
    void theJwksIsFetchedFromTheAddressItsOwnResolutionValidated() throws Exception {
        final String jwks = new JWKSet(new RSAKeyGenerator(2048).keyID("k1").generate().toPublicJWK()).toString();
        try (RebindingTarget target = RebindingTarget.http("wif.rebind.test")) {
            target.respond(s -> new RebindingTarget.Answer(200, "application/json", jwks));
            final var verifier = new WorkloadTokenVerifier(target.guard());
            final var source = verifier.jwkSource(target.url("http", "/jwks"));
            target.resetLookups(); // the fetch's own resolution is the validated one, every later one rebinds

            assertThat(source.get(new JWKSelector(new JWKMatcher.Builder().build()), null)).hasSize(1);
            assertThat(target.requests()).hasSize(1);
            assertThat(target.requests().get(0).header("Host")).isEqualTo("wif.rebind.test:" + target.port());
            assertThat(target.lookups()).isEqualTo(1);
        }
    }

    @Test
    void theIssuerDiscoveryIsFetchedFromTheValidatedAddressOnly() throws Exception {
        try (RebindingTarget target = RebindingTarget.http("issuer.rebind.test")) {
            target.respond(s -> new RebindingTarget.Answer(200, "application/json",
                    "{\"jwks_uri\":\"https://issuer.example/jwks\"}"));

            final String jwksUri = new WorkloadTokenVerifier(target.guard())
                    .discoverJwksUri(target.url("http", "/.well-known/openid-configuration"));

            assertThat(jwksUri).isEqualTo("https://issuer.example/jwks");
            assertThat(target.requests()).hasSize(1);
            assertThat(target.requests().get(0).header("Accept")).isEqualTo("application/json");
            assertThat(target.lookups()).isEqualTo(1);
        }
    }
}
