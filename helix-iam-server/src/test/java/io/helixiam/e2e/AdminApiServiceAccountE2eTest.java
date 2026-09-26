/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 1.0 item 4: the admin API accepts a service account's bearer access token (client_credentials), authorised
 * by the same realm RBAC as a console session, scoped to the service account's own realm, and without CSRF
 * (CSRF protects cookie sessions only). Before the fix every bearer call was a 401.
 */
class AdminApiServiceAccountE2eTest extends AbstractE2eTest {

    @Test
    void serviceAccountWithAdminRole_canCallItsRealmsAdminApi_withoutCsrf() {
        final String realm = E2eSeed.unique("ops");
        seed().realm(realm);
        final String token = serviceAccountToken(realm, "admin");

        final E2eHttp http = newBrowser();
        final E2eHttp.Response list = http.get("/admin/realms/" + realm + "/clients", bearer(token));
        assertThat(list.status()).as(list.toString()).isEqualTo(200);

        final String clientId = E2eSeed.unique("web");
        final E2eHttp.Response created = http.sendJson("POST", "/admin/realms/" + realm + "/clients",
                Map.of("clientId", clientId, "grantTypes", List.of("client_credentials")), bearer(token));
        assertThat(created.status()).as(created.toString()).isEqualTo(201);
    }

    @Test
    void serviceAccountWithoutAdminRole_isForbidden() {
        final String realm = E2eSeed.unique("ops");
        seed().realm(realm);
        final String token = serviceAccountToken(realm, null);

        final E2eHttp.Response r = newBrowser().get("/admin/realms/" + realm + "/clients", bearer(token));
        assertThat(r.status()).as(r.toString()).isEqualTo(403);
    }

    @Test
    void serviceAccountAdminOfOneRealm_isRefusedInAnotherRealm() {
        final String home = E2eSeed.unique("ops");
        final String other = E2eSeed.unique("ops");
        seed().realm(home);
        seed().realm(other);
        final String token = serviceAccountToken(home, "admin");

        final E2eHttp http = newBrowser();
        assertThat(http.get("/admin/realms/" + other + "/clients", bearer(token)).status()).isEqualTo(403);
        assertThat(http.sendJson("POST", "/admin/realms/" + other + "/clients",
                Map.of("clientId", E2eSeed.unique("x"), "grantTypes", List.of("client_credentials")), bearer(token))
                .status()).isEqualTo(403);
    }

    @Test
    void masterRealmAdminServiceAccount_provisionsAndAdministersANewRealm() {
        // Keycloak model: the master realm is the administrative realm; its admins manage every realm. This is
        // how a realm gets created at all (PUT settings upserts it) — e.g. Monthfold's monthfold-provisioner.
        final String token = serviceAccountToken(MASTER, "admin");
        final String realm = E2eSeed.unique("provisioned");
        final E2eHttp http = newBrowser();

        final E2eHttp.Response created = http.sendJson("PUT", "/admin/realms/" + realm + "/settings",
                Map.of("displayName", "Provisioned", "accessTokenTtlSeconds", 300, "refreshTokenTtlSeconds", 86400,
                        "enabled", true, "passwordMinLength", 12), bearer(token));
        assertThat(created.status()).as(created.toString()).isEqualTo(200);
        assertThat(oidc(realm).issuer()).isEqualTo(baseUrl() + "/realms/" + realm);

        final E2eHttp.Response client = http.sendJson("POST", "/admin/realms/" + realm + "/clients",
                Map.of("clientId", "web", "grantTypes", List.of("authorization_code")), bearer(token));
        assertThat(client.status()).as(client.toString()).isEqualTo(201);

        // A master-realm service account without the admin role gets nothing.
        final String plain = serviceAccountToken(MASTER, null);
        assertThat(http.get("/admin/realms/" + realm + "/clients", bearer(plain)).status()).isEqualTo(403);
    }

    @Test
    void invalidOrForeignBearerTokens_areUnauthorized() {
        final E2eHttp http = newBrowser();
        final E2eHttp.Response garbage = http.get("/admin/realms/master/clients", bearer("not-a-token"));
        assertThat(garbage.status()).as(garbage.toString()).isEqualTo(401);
        assertThat(garbage.header("WWW-Authenticate")).hasValueSatisfying(h -> assertThat(h).startsWith("Bearer"));
    }

    @Test
    void userAccessToken_isNotAnAdminCredential() {
        // Only machine tokens (client_credentials) are accepted as bearer credentials on the admin API; an
        // interactive user's access token held by some app must not turn into console access.
        final E2eSeed.SeededClient app = seed().confidentialClient(MASTER, E2eSeed.unique("app"), List.of("openid"));
        final OidcFlow.Tokens tokens = oidc(MASTER).authorizationCode(app.clientId(), app.secret(), app.redirectUri(),
                ADMIN_USERNAME, ADMIN_PASSWORD, "openid");
        final E2eHttp.Response r = newBrowser().get("/admin/realms/master/clients", bearer(tokens.accessToken()));
        assertThat(r.status()).as(r.toString()).isEqualTo(401);
    }

    /** A client_credentials token for a new service account in {@code realm}, holding realm role {@code role}. */
    private String serviceAccountToken(final String realm, final String role) {
        final E2eSeed.SeededClient sa = seed().serviceAccountClient(realm, E2eSeed.unique("automation"), List.of("openid"));
        if (role != null) {
            final E2eHttp.Response granted = adminSession(realm).post("/admin/realms/" + realm + "/clients/"
                    + sa.clientId() + "/service-account/roles", Map.of("roleName", role, "roleType", "REALM"));
            assertThat(granted.status()).as(granted.toString()).isEqualTo(201);
        }
        return oidc(realm).clientCredentials(sa.clientId(), sa.secret(), "openid").accessToken();
    }

    private static String[] bearer(final String token) {
        return new String[] {"Authorization", "Bearer " + token, "Accept", "application/json"};
    }
}
