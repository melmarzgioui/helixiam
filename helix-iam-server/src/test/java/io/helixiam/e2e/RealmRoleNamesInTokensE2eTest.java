/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Open issue E8: pins the documented role naming in tokens ({@code docs/role-names-in-tokens.md}). A user's realm
 * roles appear in {@code realm_access.roles} qualified with the realm ({@code <role>_<realm>}); a service account's
 * realm roles appear as the plain role name.
 */
class RealmRoleNamesInTokensE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Role-Names-Passw0rd!";

    @Test
    void userRealmRolesAreRealmQualified_serviceAccountRealmRolesArePlain() {
        final String realm = E2eSeed.unique("rolenames");
        seed().realm(realm);
        final E2eAdminSession admin = adminSession(realm);
        assertThat(admin.post("/admin/realms/" + realm + "/roles", Map.of("name", "accountant")).status()).isEqualTo(201);
        String roleId = null;
        for (final JsonNode r : admin.get("/admin/realms/" + realm + "/roles").json()) {
            if ("accountant".equals(r.path("name").asText())) {
                roleId = r.path("roleId").asText();
            }
        }
        final E2eSeed.SeededUser joe = seed().user(realm, E2eSeed.unique("joe"), PASSWORD);
        assertThat(admin.post("/admin/realms/" + realm + "/users/" + joe.userId() + "/roles", Map.of("roleId", roleId))
                .status()).isEqualTo(204);

        final E2eSeed.SeededClient app = seed().confidentialClient(realm, E2eSeed.unique("app"), List.of("openid"));
        final OidcFlow.Tokens user = oidc(realm).authorizationCode(app.clientId(), app.secret(), app.redirectUri(),
                joe.username(), PASSWORD, "openid");
        assertThat(realmRoles(user.accessToken())).contains("accountant_" + realm).doesNotContain("accountant");
        assertThat(realmRoles(user.idToken())).contains("accountant_" + realm);

        final E2eSeed.SeededClient sa = seed().serviceAccountClient(realm, E2eSeed.unique("ledger"), List.of("openid"));
        assertThat(admin.post("/admin/realms/" + realm + "/clients/" + sa.clientId() + "/service-account/roles",
                Map.of("roleName", "accountant", "roleType", "REALM")).status()).isEqualTo(201);
        final String machine = oidc(realm).clientCredentials(sa.clientId(), sa.secret(), "openid").accessToken();
        assertThat(realmRoles(machine)).contains("accountant").doesNotContain("accountant_" + realm);
    }

    @SuppressWarnings("unchecked")
    private static List<String> realmRoles(final String jwt) {
        final Object realmAccess = OidcFlow.claims(jwt).get("realm_access");
        assertThat(realmAccess).as("realm_access").isInstanceOf(Map.class);
        return (List<String>) ((Map<String, Object>) realmAccess).get("roles");
    }
}
