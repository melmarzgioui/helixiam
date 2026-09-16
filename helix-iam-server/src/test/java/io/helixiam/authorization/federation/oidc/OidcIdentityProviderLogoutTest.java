/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.oidc;

import io.helixiam.authorization.federation.UpstreamLogoutClient;
import io.helixiam.authorization.federation.spi.IdentityProvider.LogoutContext;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Helix IAM SSO P9: the OIDC broker propagates Single Logout to the upstream IdP's
 * {@code end_session_endpoint} with the captured {@code id_token_hint} — best-effort, never blocking.
 */
class OidcIdentityProviderLogoutTest {

    private static final class CapturingClient implements UpstreamLogoutClient {
        String url;
        boolean fail;
        @Override public void get(final String u) {
            this.url = u;
            if (fail) {
                throw new RuntimeException("upstream down");
            }
        }
    }

    private OidcProviderConfig config(final String endSession) {
        return new OidcProviderConfig("upstream", "Upstream", "helix-client", "secret",
                "https://idp/authorize", "https://idp/token", "https://idp/jwks", "https://idp", List.of("openid"),
                endSession);
    }

    @Test
    void logout_hitsTheEndSessionEndpointWithTheIdTokenHint() {
        final CapturingClient client = new CapturingClient();
        final OidcIdentityProvider provider = new OidcIdentityProvider(config("https://idp/logout"), null, () -> "n", client);

        provider.logout(new LogoutContext("master", "user-1", "upstream", "the.id.token", null, null));

        assertThat(client.url).startsWith("https://idp/logout?")
                .contains("client_id=helix-client")
                .contains("id_token_hint=the.id.token");
    }

    @Test
    void logout_isANoOp_whenTheProviderHasNoEndSessionEndpoint() {
        final CapturingClient client = new CapturingClient();
        final OidcIdentityProvider provider = new OidcIdentityProvider(config(null), null, () -> "n", client);

        provider.logout(new LogoutContext("master", "user-1", "upstream", "the.id.token", null, null));

        assertThat(client.url).isNull();
    }

    @Test
    void logout_swallowsUpstreamFailures() {
        final CapturingClient client = new CapturingClient();
        client.fail = true;
        final OidcIdentityProvider provider = new OidcIdentityProvider(config("https://idp/logout"), null, () -> "n", client);

        assertThatCode(() -> provider.logout(new LogoutContext("master", "u", "upstream", "t", null, null)))
                .doesNotThrowAnyException();
    }
}
