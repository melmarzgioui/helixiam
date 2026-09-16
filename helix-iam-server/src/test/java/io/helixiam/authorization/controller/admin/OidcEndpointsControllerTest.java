/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.realm.RealmAdminPublisher;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Helix IAM multi-tenant (MT-3/MT-4): the console "OIDC endpoints" card mirrors the realm-prefixed
 * discovery document — issuer and every endpoint live under {@code {base}/realms/{realm}/…}.
 */
class OidcEndpointsControllerTest {

    private final AuthorizationServerSettings settings = AuthorizationServerSettings.builder()
            .issuer("https://idp.example").build();
    private final RealmAdminPublisher realmAdminPublisher = mock(RealmAdminPublisher.class);
    private final OidcEndpointsController controller = new OidcEndpointsController(settings, realmAdminPublisher);

    @Test
    void endpointsAreRealmPrefixed_fromTheConfiguredRealmIssuer() {
        when(realmAdminPublisher.get("gov")).thenReturn(
                new io.helixiam.authorization.amqp.realm.RealmSettingsDto("gov", "Gov", "https://idp.gov.nl",
                        3600, 5184000, false, false, 12, true, 1800, 36000, false, 2592000,
                        false, 5, 900, 900, false,
                        false, false, false, false, false, 0,
                        false,
                        "none", null, null,
                        0, true,
                        false, 40, 70, "allow", "step_up", "deny",
                        null, null, null, null, null, true));

        final OidcEndpointsController.OidcEndpoints endpoints = controller.get("gov");

        assertThat(endpoints.issuer()).isEqualTo("https://idp.gov.nl/realms/gov");
        assertThat(endpoints.token()).isEqualTo("https://idp.gov.nl/realms/gov/oauth2/token");
        assertThat(endpoints.discovery()).isEqualTo("https://idp.gov.nl/realms/gov/.well-known/openid-configuration");
        assertThat(endpoints.jwks()).startsWith("https://idp.gov.nl/realms/gov/");
    }

    @Test
    void fallsBackToServerIssuer_whenRealmHasNoneConfigured() {
        when(realmAdminPublisher.get("master")).thenReturn(null);

        final OidcEndpointsController.OidcEndpoints endpoints = controller.get("master");

        assertThat(endpoints.issuer()).isEqualTo("https://idp.example/realms/master");
        assertThat(endpoints.token()).isEqualTo("https://idp.example/realms/master/oauth2/token");
    }
}
