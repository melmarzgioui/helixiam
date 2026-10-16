/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import io.helixiam.authorization.service.adminrbac.AdminDefaultRoleCheck;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.JsonNode;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Security review (found in rc.11, confirmed live): an admin can never grant admin permissions they do not hold. A
 * {@code manage-users} admin used to self-assign the {@code admin} role and become realm admin; a {@code manage-roles}
 * admin could make {@code admin} the default role. Every path that hands out a role is covered: user roles, group
 * roles and group membership, service-account roles, the admin-permission editor, realm import, SCIM and the default
 * role.
 */
class AdminGrantEscalationE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Escalation-Passw0rd!";

    private String realm;
    private E2eAdminSession admin;
    private String adminRoleId;
    private String auditorRoleId;
    private String helperRoleId;
    private String userRoleId;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("esc");
        seed().realm(realm);
        admin = adminSession();
        helperRoleId = admin.post(base() + "/roles", Map.of("name", "helper")).json().path("roleId").asText();
        for (final JsonNode r : admin.get(base() + "/roles").json()) {
            switch (r.path("name").asText()) {
                case "admin" -> adminRoleId = r.path("roleId").asText();
                case "auditor" -> auditorRoleId = r.path("roleId").asText();
                case "user" -> userRoleId = r.path("roleId").asText();
                case "helper" -> helperRoleId = r.path("roleId").asText();
                default -> { }
            }
        }
        assertThat(adminRoleId).isNotBlank();
        assertThat(auditorRoleId).isNotBlank();
    }

    @Test
    void manageUsers_cannotSelfAssignAdmin_norAnyRoleWithPermissionsItLacks() {
        final Scoped s = scoped("manage-users");
        // The exact live scenario: self-assign the admin role.
        assertThat(s.session().post(base() + "/users/" + s.userId() + "/roles", Map.of("roleId", adminRoleId)).status())
                .isEqualTo(403);
        // auditor carries view-* permissions this admin does not hold.
        assertThat(s.session().post(base() + "/users/" + s.userId() + "/roles", Map.of("roleId", auditorRoleId))
                .status()).isEqualTo(403);
        // A role without admin permissions is fine.
        assertThat(s.session().post(base() + "/users/" + s.userId() + "/roles", Map.of("roleId", helperRoleId))
                .status()).isEqualTo(204);
        // Nor can it remove the admin role from a realm admin.
        final E2eSeed.SeededUser other = seed().user(realm, E2eSeed.unique("adm"), PASSWORD);
        assertThat(admin.post(base() + "/users/" + other.userId() + "/roles", Map.of("roleId", adminRoleId)).status())
                .isEqualTo(204);
        assertThat(s.session().delete(base() + "/users/" + other.userId() + "/roles/" + adminRoleId).status())
                .isEqualTo(403);
        assertThat(roleNames(s.userId())).doesNotContain("admin", "auditor").contains("helper");
    }

    @Test
    void manageRoles_cannotMakeAdminTheDefaultRole() {
        final Scoped s = scoped("manage-roles");
        final E2eHttp.Response r = s.session().put(base() + "/roles/" + adminRoleId + "/default", Map.of());
        assertThat(r.status()).as(r.toString()).isEqualTo(400);
        assertThat(r.json().path("fieldErrors").has("roleId")).isTrue();
        // Not even a realm admin can: every new user would become an administrator.
        assertThat(admin.put(base() + "/roles/" + auditorRoleId + "/default", Map.of()).status()).isEqualTo(400);
        // A role without admin permissions can be the default.
        assertThat(s.session().put(base() + "/roles/" + helperRoleId + "/default", Map.of()).status()).isEqualTo(200);
        assertThat(admin.put(base() + "/roles/" + userRoleId + "/default", Map.of()).status()).isEqualTo(200);
        // The admin-permission editor needs realm-admin; and the default role cannot be given admin permissions.
        assertThat(s.session().put(base() + "/admin-roles/" + helperRoleId,
                Map.of("permissions", List.of("manage-users"))).status()).isEqualTo(403);
        assertThat(admin.put(base() + "/admin-roles/" + userRoleId,
                Map.of("permissions", List.of("view-users"))).status()).isEqualTo(400);
    }

    @Test
    void groups_cannotCarryOrHandOutAdminPermissionsItLacks() {
        final Scoped s = scoped("manage-organizations");
        final String group = s.session().post(base() + "/groups", Map.of("name", E2eSeed.unique("g"))).json()
                .path("groupId").asText();
        assertThat(s.session().put(base() + "/groups/" + group + "/roles/" + adminRoleId, Map.of()).status())
                .isEqualTo(403);
        // A group a realm admin gave the admin role: joining it is granting admin.
        final String admins = admin.post(base() + "/groups", Map.of("name", E2eSeed.unique("admins"))).json()
                .path("groupId").asText();
        assertThat(admin.put(base() + "/groups/" + admins + "/roles/" + adminRoleId, Map.of()).status()).isEqualTo(204);
        assertThat(s.session().put(base() + "/groups/" + admins + "/members/" + s.userId(), Map.of()).status())
                .isEqualTo(403);
        assertThat(s.session().put(base() + "/groups/" + group + "/members/" + s.userId(), Map.of()).status())
                .isEqualTo(204);
    }

    @Test
    void manageClients_cannotGiveAServiceAccountTheAdminRole() {
        final Scoped s = scoped("manage-clients");
        final E2eSeed.SeededClient sa = seed().serviceAccountClient(realm, E2eSeed.unique("svc"), List.of("openid"));
        final String path = base() + "/clients/" + sa.clientId() + "/service-account/roles";
        assertThat(s.session().post(path, Map.of("roleName", "admin", "roleType", "REALM")).status()).isEqualTo(403);
        assertThat(s.session().post(path, Map.of("roleName", "auditor", "roleType", "REALM")).status()).isEqualTo(403);
        assertThat(s.session().post(path, Map.of("roleName", "helper", "roleType", "REALM")).status()).isEqualTo(201);
        assertThat(admin.post(path, Map.of("roleName", "admin", "roleType", "REALM")).status()).isEqualTo(201);
    }

    @Test
    void manageRealm_cannotImportAdminPermissions() {
        final Scoped s = scoped("manage-realm");
        final E2eHttp.Response r = s.session().post(base() + "/import", Map.of("formatVersion", 2,
                "adminRoles", List.of(Map.of("roleName", "helper", "permissions", List.of("realm-admin")))));
        assertThat(r.status()).as(r.toString()).isEqualTo(403);
        final JsonNode grants = admin.get(base() + "/admin-roles").json();
        for (final JsonNode g : grants.path("roles").isMissingNode() ? grants : grants.path("roles")) {
            if ("helper".equals(g.path("roleName").asText())) {
                assertThat(g.path("permissions").toString()).doesNotContain("realm-admin");
            }
        }
    }

    @Test
    void scim_cannotAddMembersToAnAdminGroup() {
        final String token = admin.put(base() + "/provisioning", Map.of("dcrOpen", false, "rotateScimToken", true,
                "clearScimToken", false)).json().path("newScimToken").asText();
        assertThat(token).isNotBlank();
        final String admins = admin.post(base() + "/groups", Map.of("name", E2eSeed.unique("admins"))).json()
                .path("groupId").asText();
        assertThat(admin.put(base() + "/groups/" + admins + "/roles/" + adminRoleId, Map.of()).status()).isEqualTo(204);
        final E2eSeed.SeededUser u = seed().user(realm, E2eSeed.unique("scimu"), PASSWORD);
        final E2eHttp.Response r = newBrowser().sendJson("PATCH", "/realms/" + realm + "/scim/v2/Groups/" + admins,
                Map.of("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:PatchOp"), "Operations",
                        List.of(Map.of("op", "add", "path", "members", "value", List.of(Map.of("value", u.userId()))))),
                "Authorization", "Bearer " + token, "Accept", "application/scim+json");
        assertThat(r.status()).as(r.toString()).isEqualTo(403);
        assertThat(admin.get(base() + "/groups/" + admins + "/members").body()).doesNotContain(u.userId());
    }

    @Test
    void existingAdminDefaultRoles_areReported_andNotHandedToNewUsers() {
        final JdbcTemplate jdbc = context.getBean(JdbcTemplate.class);
        final org.springframework.transaction.support.TransactionTemplate tx =
                new org.springframework.transaction.support.TransactionTemplate(
                        context.getBean(org.springframework.transaction.PlatformTransactionManager.class));
        // Older data: auditor (view-* grants) made the default role directly in the database.
        tx.executeWithoutResult(t -> {
            jdbc.update("UPDATE user_roles SET default_role = false WHERE tenant_id = ?", realm);
            jdbc.update("UPDATE user_roles SET default_role = true WHERE role_id = ?", auditorRoleId);
        });
        try {
            assertThat(context.getBean(AdminDefaultRoleCheck.class).check())
                    .anyMatch(r -> auditorRoleId.equals(r.getRoleId()));
            final E2eSeed.SeededUser fresh = seed().user(realm, E2eSeed.unique("new"), PASSWORD);
            assertThat(roleNames(fresh.userId())).doesNotContain("auditor");
        } finally {
            tx.executeWithoutResult(t -> jdbc.update(
                    "UPDATE user_roles SET default_role = (role_id = ?) WHERE tenant_id = ?", userRoleId, realm));
        }
    }

    // ------------------------------------------------------------------------------------------------ helpers

    private String base() {
        return "/admin/realms/" + realm;
    }

    private List<String> roleNames(final String userId) {
        final List<String> names = new java.util.ArrayList<>();
        admin.get(base() + "/users/" + userId + "/roles").json().forEach(r -> names.add(r.path("name").asText()));
        return names;
    }

    private record Scoped(E2eAdminSession session, String userId) {
    }

    /** A realm user whose only admin permission is {@code permission}, logged in. */
    private Scoped scoped(final String permission) {
        final String roleName = E2eSeed.unique("esc-" + permission);
        final E2eHttp.Response role = admin.post(base() + "/roles", Map.of("name", roleName));
        assertThat(role.status()).as(role.toString()).isEqualTo(201);
        String roleId = role.json().path("roleId").asText();
        if (roleId.isBlank()) {
            for (final JsonNode r : admin.get(base() + "/roles").json()) {
                if (roleName.equals(r.path("name").asText())) {
                    roleId = r.path("roleId").asText();
                }
            }
        }
        assertThat(admin.put(base() + "/admin-roles/" + roleId, Map.of("permissions", List.of(permission))).status())
                .isEqualTo(200);
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("esc-u"), PASSWORD);
        assertThat(admin.post(base() + "/users/" + user.userId() + "/roles", Map.of("roleId", roleId)).status())
                .isEqualTo(204);
        return new Scoped(E2eAdminSession.login(newBrowser(), realm, user.username(), PASSWORD), user.userId());
    }
}
