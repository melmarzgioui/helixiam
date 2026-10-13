/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.oidc;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E7.3/E7.4/E7.6: the advanced-OIDC client-policy presets register clients with the correct
 * grants + authentication + token settings. (PAR/DPoP/token-exchange protocol handling is Spring
 * Authorization Server's runtime job; this verifies Helix's client policy.)
 */
class HelixClientPoliciesTest {

    @Test
    void tokenExchangeClientAllowsTheRfc8693Grant() {
        final RegisteredClient client = HelixClientPolicies.tokenExchangeClient("svc", "secret");

        assertThat(client.getAuthorizationGrantTypes()).contains(AuthorizationGrantType.TOKEN_EXCHANGE);
        assertThat(client.getClientAuthenticationMethods()).contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    }

    @Test
    void fapiClientUsesPrivateKeyJwtMandatoryPkceAndShortNonReusedTokens() {
        final RegisteredClient client = HelixClientPolicies.fapiClient(
                "fapi-app", "https://app.example/jwks", "https://app.example/cb", "accounts");

        assertThat(client.getClientAuthenticationMethods()).contains(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();                 // PKCE mandatory
        assertThat(client.getClientSettings().getJwkSetUrl()).isEqualTo("https://app.example/jwks");
        assertThat(client.getTokenSettings().getAccessTokenTimeToLive()).isEqualTo(java.time.Duration.ofMinutes(5));
        assertThat(client.getTokenSettings().isReuseRefreshTokens()).isFalse();
        assertThat(client.getAuthorizationGrantTypes()).contains(AuthorizationGrantType.AUTHORIZATION_CODE);
    }

    @Test
    void confidentialClientIsAStandardAuthCodeClientWithoutMandatoryPkce() {
        final RegisteredClient client = HelixClientPolicies.confidentialClient(
                "web", "secret", "https://web.example/cb", "profile");

        assertThat(client.getClientAuthenticationMethods()).contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        assertThat(client.getClientSettings().isRequireProofKey()).isFalse();
        assertThat(client.getScopes()).contains("openid", "profile");
    }

    /**
     * Spring Security 7 changed {@code ClientSettings.builder()}'s default to {@code requireProofKey(true)} (Spring
     * Authorization Server 1.x: false). Every client HelixIAM builds pins it, so the default never decides: PKCE is
     * mandatory for public and FAPI clients and optional for confidential and machine clients, as in 1.0.
     */
    @Test
    void everyClientHelixBuilds_pinsRequireProofKey_independentOfTheFrameworkDefault() {
        assertThat(org.springframework.security.oauth2.server.authorization.settings.ClientSettings.builder().build()
                .isRequireProofKey()).as("Spring Security 7's default, which none of these may inherit").isTrue();

        assertThat(HelixClientPolicies.tokenExchangeClient("svc", "secret").getClientSettings().isRequireProofKey())
                .isFalse();
        assertThat(HelixClientPolicies.confidentialClient("web", "s", "https://web.example/cb").getClientSettings()
                .isRequireProofKey()).isFalse();
        assertThat(HelixClientPolicies.fapiClient("f", "https://f.example/jwks", "https://f.example/cb")
                .getClientSettings().isRequireProofKey()).isTrue();

        final io.helixiam.authorization.domain.ServiceProviderOAuthClient confidential =
                new io.helixiam.authorization.domain.ServiceProviderOAuthClient();
        assertThat(confidential.getClientSettings().isRequireProofKey()).as("publicClient unset").isFalse();
        confidential.setPublicClient(false);
        assertThat(confidential.getClientSettings().isRequireProofKey()).isFalse();
        final io.helixiam.authorization.domain.ServiceProviderOAuthClient publicClient =
                new io.helixiam.authorization.domain.ServiceProviderOAuthClient();
        publicClient.setPublicClient(true);
        assertThat(publicClient.getClientSettings().isRequireProofKey()).isTrue();
        // What the repository hands SAS (RegisteredClient.from keeps the client's own settings).
        assertThat(RegisteredClient.from(HelixClientPolicies.tokenExchangeClient("svc", "secret")).build()
                .getClientSettings().isRequireProofKey()).isFalse();
    }
}
