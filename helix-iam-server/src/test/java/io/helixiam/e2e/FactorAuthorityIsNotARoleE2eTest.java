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
 * Spring Security 7 marks every password login with the authority {@code FACTOR_PASSWORD}. It says how the user signed
 * in and is never a role: the {@code FACTOR_} prefix cannot be used for a realm role, a client role or a service-account
 * role, and no token ever carries a {@code FACTOR_*} value.
 */
class FactorAuthorityIsNotARoleE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Factor-Not-Role-Passw0rd!";

    @Test
    void aPasswordLoginsTokens_carryNoFactor_andFactorRoleNamesAreRefused() {
        final String realm = E2eSeed.unique("factor");
        seed().realm(realm);
        final E2eAdminSession admin = adminSession(realm);

        for (final String name : List.of("FACTOR_PASSWORD", "factor_password", "FACTOR_OTT")) {
            assertThat(admin.post("/admin/realms/" + realm + "/roles", Map.of("name", name)).status())
                    .as("realm role %s", name).isEqualTo(400);
        }
        for (final JsonNode role : admin.get("/admin/realms/" + realm + "/roles").json()) {
            assertThat(role.path("name").asText()).doesNotStartWithIgnoringCase("FACTOR_");
        }
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
        assertThat(admin.post("/admin/realms/" + realm + "/clients/" + app.clientId() + "/roles",
                Map.of("name", "FACTOR_PASSWORD")).status()).isEqualTo(400);
        final E2eSeed.SeededClient sa = seed().serviceAccountClient(realm, E2eSeed.unique("ledger"), List.of("openid"));
        assertThat(admin.post("/admin/realms/" + realm + "/clients/" + sa.clientId() + "/service-account/roles",
                Map.of("roleName", "FACTOR_PASSWORD", "roleType", "REALM")).status()).isEqualTo(400);

        final OidcFlow.Tokens user = oidc(realm).authorizationCode(app.clientId(), app.secret(), app.redirectUri(),
                joe.username(), PASSWORD, "openid");
        for (final String jwt : List.of(user.accessToken(), user.idToken())) {
            assertThat(realmRoles(jwt)).contains("accountant_" + realm).noneMatch(r -> r.toUpperCase().startsWith("FACTOR_"));
            assertThat(OidcFlow.claims(jwt).toString()).doesNotContainIgnoringCase("FACTOR_");
        }
        final OidcFlow.Tokens refreshed = oidc(realm).refresh(app.clientId(), app.secret(), user.refreshToken());
        assertThat(OidcFlow.claims(refreshed.accessToken()).toString()).doesNotContainIgnoringCase("FACTOR_");
    }

    @SuppressWarnings("unchecked")
    private static List<String> realmRoles(final String jwt) {
        final Object realmAccess = OidcFlow.claims(jwt).get("realm_access");
        assertThat(realmAccess).as("realm_access").isInstanceOf(Map.class);
        return (List<String>) ((Map<String, Object>) realmAccess).get("roles");
    }
}
