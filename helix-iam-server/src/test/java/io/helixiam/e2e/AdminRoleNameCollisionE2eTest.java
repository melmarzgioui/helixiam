/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

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

    @Test
    void ordinaryRoleNames_includingUnderscores_stillWork() {
        assertThat(homeAdmin.post("/admin/realms/" + home + "/roles", Map.of("name", "app_admin")).status()).isEqualTo(201);
        assertThat(homeAdmin.post("/admin/realms/" + home + "/roles", Map.of("name", "administrator")).status()).isEqualTo(201);
    }
}
