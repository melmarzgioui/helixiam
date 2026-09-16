/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.device;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Story 4 (CLI auth): authenticates a PUBLIC client (auth method NONE) at the RFC 8628 device
 * authorization endpoint by {@code client_id} alone. SAS's built-in public-client converter only
 * activates for a PKCE token request, so a public CLI client needs this provider to start the device flow.
 */
class DeviceClientAuthenticationProviderTest {

    private RegisteredClientRepository repository;
    private DeviceClientAuthenticationProvider provider;

    private static RegisteredClient publicClient() {
        return RegisteredClient.withId("1").clientId("kubedna-cli")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:device_code"))
                .scope("openid").build();
    }

    private static RegisteredClient confidentialClient() {
        return RegisteredClient.withId("2").clientId("portal").clientSecret("{noop}s")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("openid").build();
    }

    private static OAuth2ClientAuthenticationToken noneToken(final String clientId) {
        return new OAuth2ClientAuthenticationToken(clientId, ClientAuthenticationMethod.NONE, null, Map.of());
    }

    @BeforeEach
    void setUp() {
        repository = mock(RegisteredClientRepository.class);
        provider = new DeviceClientAuthenticationProvider(repository);
    }

    @Test
    void authenticatesPublicClientByClientId() {
        final RegisteredClient rc = publicClient();
        when(repository.findByClientId("kubedna-cli")).thenReturn(rc);

        final Authentication out = provider.authenticate(noneToken("kubedna-cli"));

        assertTrue(out.isAuthenticated());
        assertSame(rc, ((OAuth2ClientAuthenticationToken) out).getRegisteredClient());
    }

    @Test
    void rejectsUnknownClient() {
        when(repository.findByClientId("ghost")).thenReturn(null);
        assertThrows(OAuth2AuthenticationException.class, () -> provider.authenticate(noneToken("ghost")));
    }

    @Test
    void rejectsClientThatDoesNotAllowPublicAuth() {
        when(repository.findByClientId("portal")).thenReturn(confidentialClient());
        assertThrows(OAuth2AuthenticationException.class, () -> provider.authenticate(noneToken("portal")));
    }

    @Test
    void ignoresNonPublicAuthMethod_soOtherProvidersHandleIt() {
        final OAuth2ClientAuthenticationToken basic =
                new OAuth2ClientAuthenticationToken("portal", ClientAuthenticationMethod.CLIENT_SECRET_BASIC, "s", Map.of());
        assertNull(provider.authenticate(basic), "not a public-client auth — defer to the next provider");
    }

    @Test
    void supportsClientAuthenticationToken() {
        assertTrue(provider.supports(OAuth2ClientAuthenticationToken.class));
    }
}
