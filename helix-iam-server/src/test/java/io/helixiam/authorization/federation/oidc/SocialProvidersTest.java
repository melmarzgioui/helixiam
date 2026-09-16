package io.helixiam.authorization.federation.oidc;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Helix IAM E5.2: social-login presets supply the well-known OIDC endpoints so the broker works
 * from just a client id + secret. */
class SocialProvidersTest {

    @Test
    void googlePresetHasOidcEndpointsAndOpenidScope() {
        final OidcProviderConfig google = SocialProviders.google("cid", "sec");
        assertThat(google.alias()).isEqualTo("google");
        assertThat(google.authorizationEndpoint()).isEqualTo("https://accounts.google.com/o/oauth2/v2/auth");
        assertThat(google.issuer()).isEqualTo("https://accounts.google.com");
        assertThat(google.scopeParam()).contains("openid");
    }

    @Test
    void microsoftPresetUsesTheTenantInItsEndpoints() {
        final OidcProviderConfig ms = SocialProviders.microsoft("cid", "sec", "contoso");
        assertThat(ms.alias()).isEqualTo("microsoft");
        assertThat(ms.authorizationEndpoint()).contains("/contoso/");
        assertThat(ms.tokenEndpoint()).contains("/contoso/");
        assertThat(ms.issuer()).isEqualTo("https://login.microsoftonline.com/contoso/v2.0");
    }
}
