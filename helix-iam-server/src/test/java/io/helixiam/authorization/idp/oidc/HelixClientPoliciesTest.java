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
}
