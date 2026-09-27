/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Review rc.3 #2: a client without its own token lifetime uses the realm's access-token lifetime. */
class RealmTokenLifetimeE2eTest extends AbstractE2eTest {

    @Test
    void realmAccessTokenLifetime_appliesWhenTheClientSetsNone() {
        final String realm = E2eSeed.unique("ttl");
        seed().realm(realm, "TTL");
        // Master admin: nothing of this realm is cached yet (realm settings are cached for 30 s).
        final E2eHttp.Response settings = adminSession().put("/admin/realms/" + realm + "/settings", Map.of(
                "displayName", "TTL", "accessTokenTtlSeconds", 300, "refreshTokenTtlSeconds", 86400,
                "enabled", true, "passwordMinLength", 12));
        assertThat(settings.status()).as(settings.toString()).isEqualTo(200);
        final E2eSeed.SeededClient sa = seed().serviceAccountClient(realm, E2eSeed.unique("svc"), List.of("openid"));

        final OidcFlow oidc = oidc(realm);
        final OidcFlow.Tokens tokens = oidc.clientCredentials(sa.clientId(), sa.secret(), "openid");
        final JWTClaimsSet claims = oidc.verify(tokens.accessToken());
        final long lifetime = (claims.getExpirationTime().getTime() - claims.getIssueTime().getTime()) / 1000;
        assertThat(lifetime).isEqualTo(300);
        assertThat(tokens.raw().path("expires_in").asLong()).isBetween(298L, 300L);
    }
}
