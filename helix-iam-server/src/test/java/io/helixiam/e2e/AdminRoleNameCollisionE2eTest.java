/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CodeQL java/user-controlled-bypass review (RealmAdminAuthorities): a principal's authorities are
 * {@code <roleName>_<realmId>} and realm admin is exactly {@code admin_<realmId>}. Realm ids may contain
 * {@code _}, so a role NAMED {@code admin_prod} in realm {@code acme} yields the authority
 * {@code admin_prod_acme} — byte-identical to "admin of realm {@code prod_acme}". An admin of {@code acme}
 * could mint that role, grant it to any user, and that user administered {@code prod_acme}; any
 * {@code admin_*} role also satisfied the "admin of some realm" gate. Role names starting with
 * {@code admin_} are therefore reserved.
 */
class AdminRoleNameCollisionE2eTest extends AbstractE2eTest {

    private String home;
    private String victim;
    private E2eAdminSession homeAdmin;

    @BeforeEach
    void setUp() {
        home = E2eSeed.unique("acme").replace("-", "");
        victim = "prod_" + home;
        seed().realm(home);
        seed().realm(victim);
        homeAdmin = adminSession(home);
    }

    @Test
    void aRoleNamedLikeAnotherRealmsAdminAuthority_isRejected_soItCannotAdministerThatRealm() {
        final E2eHttp.Response created = homeAdmin.post("/admin/realms/" + home + "/roles", Map.of("name", "admin_prod"));
        assertThat(created.status()).as(created.toString()).isEqualTo(400);
        assertThat(created.json().path("fieldErrors").path("name").asText()).isNotBlank();
        assertThat(homeAdmin.post("/admin/realms/" + home + "/roles", Map.of("name", "ADMIN_prod")).status())
                .as("case variants are reserved too").isEqualTo(400);
    }

    /**
     * A database from before the reservation may already hold an {@code admin_}-named role (created through
     * the API or an import at the time). It must not turn into an admin authority for any realm.
     */
    @Test
    void anExistingAdminPrefixedRole_grantsNoAdminRights() {
        final E2eSeed.SeededUser mallory = seed().user(home, E2eSeed.unique("mallory"), "Legacy-Role-Passw0rd!");
        final String roleId = UUID.randomUUID().toString();
        final org.springframework.jdbc.core.JdbcTemplate jdbc = context.getBean(org.springframework.jdbc.core.JdbcTemplate.class);
        context.getBean(org.springframework.transaction.support.TransactionTemplate.class).executeWithoutResult(tx ->
                jdbc.update("INSERT INTO user_roles (role_id, name, tenant_id, system_role, default_role) VALUES (?, 'admin_prod', ?, false, false)",
                        roleId, home));
        final E2eHttp.Response granted = homeAdmin.post("/admin/realms/" + home + "/users/" + mallory.userId() + "/roles",
                Map.of("roleId", roleId));
        assertThat(granted.status()).as(granted.toString()).isEqualTo(204);

        final E2eAdminSession session = E2eAdminSession.login(newBrowser(), home, mallory.username(), mallory.password());
        assertThat(session.get("/admin/realms/" + victim + "/users").status())
                .as("admin_prod in realm " + home + " must not read as admin of " + victim).isIn(401, 403);
        assertThat(session.get("/admin/realms/" + home + "/users").status())
                .as("nor as an admin of its own realm").isIn(401, 403);
    }

    @Test
    void ordinaryRoleNames_includingUnderscores_stillWork() {
        assertThat(homeAdmin.post("/admin/realms/" + home + "/roles", Map.of("name", "app_admin")).status()).isEqualTo(201);
        assertThat(homeAdmin.post("/admin/realms/" + home + "/roles", Map.of("name", "administrator")).status()).isEqualTo(201);
    }
}
