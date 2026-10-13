/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.fapi;

import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.testsupport.RebindingTarget;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.net.InetAddress;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/** A client's JWKS is cached across request objects; an unknown kid refetches it (key rotation). */
class RequestObjectJwksCachingTest {

    @Test
    void theJwksIsCachedAndRefetchedOnAnUnknownKid() throws Exception {
        final RSAKey k1 = new RSAKeyGenerator(2048).keyID("k1").generate();
        final RSAKey k2 = new RSAKeyGenerator(2048).keyID("k2").generate();
        try (RebindingTarget target = RebindingTarget.http("client.cache.test")) {
            final AtomicReference<JWKSet> served = new AtomicReference<>(new JWKSet(k1.toPublicJWK()));
            target.respond(s -> new RebindingTarget.Answer(200, "application/json", served.get().toString()));
            final OutboundUrlGuard guard = new OutboundUrlGuard(false, List.of("client.cache.test:" + target.port()),
                    host -> new InetAddress[] {InetAddress.getByAddress(host, new byte[] {127, 0, 0, 1})});
            final RequestObjectAuthorizeFilter filter = new RequestObjectAuthorizeFilter(
                    Mockito.mock(RegisteredClientRepository.class), guard);
            final String url = target.url("http", "/jwks");

            for (int i = 0; i < 3; i++) {
                assertThat(filter.jwkSource(url).get(new JWKSelector(new JWKMatcher.Builder().keyID("k1").build()),
                        null)).hasSize(1);
            }
            assertThat(target.requests()).hasSize(1);

            served.set(new JWKSet(k2.toPublicJWK()));
            assertThat(filter.jwkSource(url).get(new JWKSelector(new JWKMatcher.Builder().keyID("k2").build()), null))
                    .hasSize(1);
            assertThat(target.requests()).hasSize(2);
        }
    }
}
