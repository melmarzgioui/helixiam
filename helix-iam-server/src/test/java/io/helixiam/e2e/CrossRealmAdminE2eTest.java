/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Review rc.3 #1 (security): an admin of one realm must not reach another realm's objects by id. Before the fix an
 * admin of realm A could reset a realm-B user's password, remove her TOTP, change her profile and sign in as her,
 * and could assign the master realm's {@code admin} role to their own user (-> admin of every realm).
 */
class CrossRealmAdminE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Cr0ss-Realm-Passw0rd!";

    private String realmA;
    private String realmB;
    private E2eAdminSession adminA;
    private E2eAdminSession master;
    private E2eSeed.SeededUser tina;   // realm B
    private E2eSeed.SeededUser maya;   // realm A

    @BeforeEach
    void setUp() {
        realmA = E2eSeed.unique("firm-a");
        realmB = E2eSeed.unique("firm-b");
        seed().realm(realmA);
        seed().realm(realmB);
        adminA = adminSession(realmA);
        master = adminSession();
        tina = seed().user(realmB, E2eSeed.unique("tina"), PASSWORD);
        maya = seed().user(realmA, E2eSeed.unique("maya"), PASSWORD);
    }

    @Test
    void aRealmAdminCannotTouchAnotherRealmsUsers() {
        final String tinaPath = "/admin/realms/" + realmA + "/users/" + tina.userId();

        assertThat(adminA.put(tinaPath, Map.of("username", tina.username(), "email", "owned@attacker.example",
                "enabled", true, "locked", false)).status()).as("profile update").isEqualTo(404);
        assertThat(adminA.put(tinaPath + "/password", Map.of("newPassword", "Attacker-Chosen-Passw0rd!")).status())
                .as("password reset").isEqualTo(404);
        assertThat(adminA.get(tinaPath + "/credentials").status()).as("credential list").isEqualTo(404);
        assertThat(adminA.delete(tinaPath + "/credentials/totp/" + tina.userId()).status()).as("credential revoke").isEqualTo(404);
        assertThat(adminA.get(tinaPath + "/required-actions").status()).as("required actions read").isEqualTo(404);
        assertThat(adminA.put(tinaPath + "/required-actions", Map.of("requiredActions", "")).status())
                .as("required actions write").isEqualTo(404);

        // Tina is untouched: same email, and her own password still signs her in.
        assertThat(master.get("/admin/realms/" + realmB + "/users/" + tina.userId()).json().path("email").asText())
                .isEqualTo(tina.dto().email());
        final E2eSeed.SeededClient app = seed().confidentialClient(realmB, E2eSeed.unique("app"), List.of("openid"));
        assertThat(oidc(realmB).authorizationCode(app.clientId(), app.secret(), app.redirectUri(), tina.username(),
                PASSWORD, "openid").accessToken()).isNotBlank();
    }

    @Test
    void aRealmAdminCannotGrantAnotherRealmsRole_norRemoveOne() {
        final String masterAdminRole = roleId(master, "master", "admin");
        final E2eHttp.Response grant = adminA.post("/admin/realms/" + realmA + "/users/" + maya.userId() + "/roles",
                Map.of("roleId", masterAdminRole));
        assertThat(grant.status()).as(grant.toString()).isIn(400, 404);
        final JsonNode mayaRoles = adminA.get("/admin/realms/" + realmA + "/users/" + maya.userId() + "/roles").json();
        assertThat(mayaRoles.toString()).doesNotContain(masterAdminRole);

        // Nor strip master's admin role from the master admin.
        final String masterAdminUser = userId(master, "master", ADMIN_USERNAME);
        assertThat(adminA.delete("/admin/realms/" + realmA + "/users/" + masterAdminUser + "/roles/" + masterAdminRole)
                .status()).isEqualTo(404);
        assertThat(master.get("/admin/realms/master/users/" + masterAdminUser + "/roles").json().toString()).contains(masterAdminRole);
    }

    @Test
    void aRealmAdminCannotReachAnotherRealmsGroupsOrganizationsKeysOrWebhooks() {
        final String groupB = master.post("/admin/realms/" + realmB + "/groups", Map.of("name", "partners"))
                .json().path("groupId").asText();
        assertThat(master.put("/admin/realms/" + realmB + "/groups/" + groupB + "/members/" + tina.userId(), Map.of())
                .status()).isBetween(200, 204);
        assertThat(adminA.get("/admin/realms/" + realmA + "/groups/" + groupB + "/members").status()).isEqualTo(404);
        assertThat(adminA.delete("/admin/realms/" + realmA + "/groups/" + groupB + "/members/" + tina.userId()).status()).isEqualTo(404);
        assertThat(adminA.put("/admin/realms/" + realmA + "/groups/" + groupB + "/members/" + maya.userId(), Map.of()).status())
                .as("adding one's own user to another realm's group").isEqualTo(404);
        assertThat(adminA.get("/admin/realms/" + realmA + "/groups/" + groupB + "/roles").status()).isEqualTo(404);

        final String orgB = master.post("/admin/realms/" + realmB + "/organizations", Map.of("name", E2eSeed.unique("org")))
                .json().path("orgId").asText();
        assertThat(master.put("/admin/realms/" + realmB + "/organizations/" + orgB + "/members/" + tina.userId(),
                Map.of("role", "owner")).status()).isBetween(200, 204);
        assertThat(adminA.get("/admin/realms/" + realmA + "/organizations/" + orgB + "/members").status()).isEqualTo(404);
        assertThat(adminA.delete("/admin/realms/" + realmA + "/organizations/" + orgB + "/members/" + tina.userId()).status())
                .isEqualTo(404);

        final String keyB = master.post("/admin/realms/" + realmB + "/keys/rotate", Map.of()).json().path("keyId").asText();
        assertThat(keyB).isNotBlank();
        assertThat(adminA.delete("/admin/realms/" + realmA + "/keys/" + keyB).status()).as("retire another realm's key").isEqualTo(404);
        assertThat(master.get("/admin/realms/" + realmB + "/keys").json().toString()).contains(keyB);

        final String hookB = master.post("/admin/realms/" + realmB + "/webhooks",
                Map.of("name", "b", "url", "https://b.example/hook", "eventTypes", "LOGIN_SUCCESS")).json().path("id").asText();
        assertThat(adminA.put("/admin/realms/" + realmA + "/webhooks/" + hookB,
                Map.of("name", "stolen", "url", "https://attacker.example/hook")).status()).isEqualTo(404);
        assertThat(master.get("/admin/realms/" + realmB + "/webhooks").json().toString()).contains("https://b.example/hook");
    }

    @Test
    void theSameCallsStillWorkInsideTheAdminsOwnRealm() {
        final String mayaPath = "/admin/realms/" + realmA + "/users/" + maya.userId();
        assertThat(adminA.put(mayaPath + "/password", Map.of("newPassword", "New-Maya-Passw0rd!")).status()).isEqualTo(204);
        assertThat(adminA.get(mayaPath + "/credentials").status()).isEqualTo(200);
        assertThat(adminA.post(mayaPath + "/roles", Map.of("roleId", roleId(adminA, realmA, "auditor"))).status()).isEqualTo(204);
    }

    private static String roleId(final E2eAdminSession session, final String realm, final String name) {
        for (final JsonNode r : session.get("/admin/realms/" + realm + "/roles").json()) {
            if (name.equals(r.path("name").asText())) {
                return r.path("roleId").asText();
            }
        }
        throw new AssertionError("no role " + name + " in " + realm);
    }

    private static String userId(final E2eAdminSession session, final String realm, final String username) {
        for (final JsonNode u : session.get("/admin/realms/" + realm + "/users").json()) {
            if (username.equals(u.path("username").asText())) {
                return u.path("userId").asText();
            }
        }
        throw new AssertionError("no user " + username + " in " + realm);
    }
}
