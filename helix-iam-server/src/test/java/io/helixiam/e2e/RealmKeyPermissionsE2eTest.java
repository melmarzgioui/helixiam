/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import tools.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Security review: importing or activating a realm signing key lets its holder mint any token of the realm, so every
 * write under {@code /keys/**} needs {@code realm-admin}; an admin with only {@code manage-realm} can still read.
 */
class RealmKeyPermissionsE2eTest extends AbstractE2eTest {

    @Test
    void manageRealmOnly_canReadKeys_butEveryWriteIsForbidden() {
        final String realm = E2eSeed.unique("keyperm");
        seed().realm(realm);
        oidc(realm).jwks();
        final E2eAdminSession admin = adminSession();
        final String keyId = admin.get(keys(realm)).json().get(0).path("keyId").asText();
        final E2eAdminSession realmOnly = scopedAdmin(admin, realm, "manage-realm");

        assertThat(realmOnly.get(keys(realm)).status()).isEqualTo(200);
        assertThat(realmOnly.post(keys(realm) + "/import", Map.of("privateKeyPem", "x", "certificateChainPem", "y"))
                .status()).isEqualTo(403);
        assertThat(realmOnly.post(keys(realm) + "/csr", Map.of("algorithm", "RS256", "subject", "CN=x")).status())
                .isEqualTo(403);
        assertThat(realmOnly.put(keys(realm) + "/" + keyId + "/certificate", Map.of("certificateChainPem", "y"))
                .status()).isEqualTo(403);
        assertThat(realmOnly.post(keys(realm) + "/" + keyId + "/activate", Map.of()).status()).isEqualTo(403);
        assertThat(realmOnly.post(keys(realm) + "/rotate", Map.of()).status()).isEqualTo(403);
        assertThat(realmOnly.delete(keys(realm) + "/" + keyId).status()).isEqualTo(403);
        // Nothing changed.
        assertThat(admin.get(keys(realm)).json().size()).isEqualTo(1);
    }

    private static String keys(final String realm) {
        return "/admin/realms/" + realm + "/keys";
    }

    /** A user of {@code realm} whose only admin permission is {@code permission}, logged in. */
    private E2eAdminSession scopedAdmin(final E2eAdminSession admin, final String realm, final String permission) {
        final String roleName = E2eSeed.unique("kp-" + permission);
        final E2eHttp.Response role = admin.post("/admin/realms/" + realm + "/roles", Map.of("name", roleName));
        assertThat(role.status()).as(role.toString()).isEqualTo(201);
        String roleId = role.json().path("roleId").asText();
        if (roleId.isBlank()) {
            for (final JsonNode r : admin.get("/admin/realms/" + realm + "/roles").json()) {
                if (roleName.equals(r.path("name").asText())) {
                    roleId = r.path("roleId").asText();
                }
            }
        }
        assertThat(admin.put("/admin/realms/" + realm + "/admin-roles/" + roleId,
                Map.of("permissions", List.of(permission))).status()).isEqualTo(200);
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("kp-scoped"), "Sc0ped-Admin-Passw0rd!");
        assertThat(admin.post("/admin/realms/" + realm + "/users/" + user.userId() + "/roles", Map.of("roleId", roleId))
                .status()).isEqualTo(204);
        return E2eAdminSession.login(newBrowser(), realm, user.username(), user.password());
    }
}
