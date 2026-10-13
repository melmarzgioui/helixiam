/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.fapi;

import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import io.helixiam.testsupport.RebindingTarget;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import static org.assertj.core.api.Assertions.assertThat;

/** M6: a client's registered JWKS (FAPI request objects) is fetched from the address the guard validated. */
class RequestObjectJwksRebindingTest {

    @Test
    void theClientJwksIsFetchedFromTheValidatedAddressOnly() throws Exception {
        final String jwks = new JWKSet(new RSAKeyGenerator(2048).keyID("k1").generate().toPublicJWK()).toString();
        try (RebindingTarget target = RebindingTarget.http("client.rebind.test")) {
            target.respond(s -> new RebindingTarget.Answer(200, "application/json", jwks));
            final RequestObjectAuthorizeFilter filter = new RequestObjectAuthorizeFilter(
                    Mockito.mock(RegisteredClientRepository.class), target.guard());

            final var keys = filter.jwkSource(target.url("http", "/jwks"))
                    .get(new JWKSelector(new JWKMatcher.Builder().build()), null);

            assertThat(keys).hasSize(1);
            assertThat(target.requests()).hasSize(1);
            assertThat(target.lookups()).isEqualTo(1);
        }
    }
}
