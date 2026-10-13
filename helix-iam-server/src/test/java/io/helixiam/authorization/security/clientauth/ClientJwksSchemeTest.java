/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.clientauth;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import io.helixiam.authorization.service.client.ClientAuthMethodAudit;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.startup.DeploymentProfile;
import io.helixiam.testsupport.LogCapture;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.net.InetAddress;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * A client's JWKS URL stored before the https rule (a legacy http row) is refused when the token endpoint would fetch
 * it, outside dev: the client assertion fails, nothing is fetched. The startup audit names such clients.
 */
class ClientJwksSchemeTest {

    private static RegisteredClient client(final String jwkSetUrl) {
        return RegisteredClient.withId(UUID.randomUUID().toString()).clientId("legacy")
                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .clientSettings(ClientSettings.builder().jwkSetUrl(jwkSetUrl)
                        .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256).build())
                .build();
    }

    private static OutboundUrlGuard counting(final AtomicInteger lookups) {
        return new OutboundUrlGuard(false, List.of(), name -> {
            lookups.incrementAndGet();
            return new InetAddress[] {InetAddress.getByAddress(name, new byte[] {93, (byte) 184, (byte) 216, 34})};
        });
    }

    @Test
    void aLegacyHttpJwksUrlFailsTheAssertionWithoutAFetchOutsideDev() {
        final AtomicInteger lookups = new AtomicInteger();
        final GuardedClientAssertionDecoderFactory production = new GuardedClientAssertionDecoderFactory(
                counting(lookups));
        for (final String url : List.of("http://keys.example.com/jwks", "http://localhost:8080/jwks", "ftp://x/jwks")) {
            assertThatThrownBy(() -> production.createDecoder(client(url)).decode("x.y.z")).as(url)
                    .isInstanceOf(BadJwtException.class).hasMessageContaining("https");
        }
        assertThat(lookups).hasValue(0);
    }

    @Test
    void devAllowsHttpToLocalhostOnly() {
        final GuardedClientAssertionDecoderFactory dev = new GuardedClientAssertionDecoderFactory(
                counting(new AtomicInteger()), DeploymentProfile.development());
        assertThat(dev.createDecoder(client("http://localhost:8080/jwks"))).isNotNull();
        assertThatThrownBy(() -> dev.createDecoder(client("http://keys.example.com/jwks")).decode("x.y.z"))
                .isInstanceOf(BadJwtException.class);
        assertThat(new GuardedClientAssertionDecoderFactory(counting(new AtomicInteger()),
                DeploymentProfile.production()).createDecoder(client("https://keys.example.com/jwks"))).isNotNull();
    }

    @Test
    void theStartupAuditNamesClientsWithANonHttpsJwksUrl() {
        final ServiceProviderRepository repo = Mockito.mock(ServiceProviderRepository.class);
        Mockito.when(repo.findPrivateKeyJwtWithoutJwksUrl()).thenReturn(List.of());
        final ServiceProviderOAuthClient legacy = new ServiceProviderOAuthClient();
        legacy.setClientId("legacy-http");
        legacy.setJwksUrl("http://keys.example.com/jwks");
        final ServiceProviderOAuthClient fine = new ServiceProviderOAuthClient();
        fine.setClientId("fine");
        fine.setJwksUrl("https://keys.example.com/jwks");
        Mockito.when(repo.findPrivateKeyJwtWithJwksUrl()).thenReturn(List.of(legacy, fine));
        try (LogCapture log = LogCapture.of(ClientAuthMethodAudit.class)) {
            assertThat(new ClientAuthMethodAudit(repo, DeploymentProfile.production()).check()).isEqualTo(1);
            assertThat(log.text()).contains("legacy-http").contains("https").doesNotContain("fine");
        }
    }
}
