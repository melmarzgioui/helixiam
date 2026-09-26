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
 * 1.0 item 3: a "scope" permission used to grant the whole resource (the type was matched case-sensitively and
 * anything that was not "SCOPE" fell through to a resource grant). Unknown types are now refused on save.
 */
class PermissionTypeE2eTest extends AbstractE2eTest {

    @Test
    void permissionTypes_areValidatedOnSave_andScopePermissionsGrantOnlyTheirScope() {
        final E2eSeed.SeededClient rs = seed().serviceAccountClient(MASTER, E2eSeed.unique("ledger-api"), List.of("openid"));
        final E2eAdminSession admin = adminSession();
        final String base = "/admin/realms/" + MASTER + "/clients/" + rs.clientId() + "/authz";

        assertThat(admin.post(base + "/scopes", Map.of("name", "read")).status()).isBetween(200, 201);
        assertThat(admin.post(base + "/scopes", Map.of("name", "delete")).status()).isBetween(200, 201);
        assertThat(admin.post(base + "/resources", Map.of("name", "invoice", "scopes", List.of("read", "delete")))
                .status()).isBetween(200, 201);
        assertThat(admin.post(base + "/policies", Map.of("name", "accountants", "type", "role", "logic", "POSITIVE",
                "roles", List.of("accountant"))).status()).isBetween(200, 201);

        final E2eHttp.Response unknown = admin.post(base + "/permissions", Map.of("name", "p-bogus", "type", "bogus",
                "resourceName", "invoice", "policies", List.of("accountants")));
        assertThat(unknown.status()).as(unknown.toString()).isEqualTo(400);
        assertThat(unknown.json().path("fieldErrors").has("type")).as(unknown.toString()).isTrue();

        final E2eHttp.Response mixed = admin.post(base + "/permissions", Map.of("name", "p-delete", "type", "Scope",
                "resourceName", "invoice", "scopeName", "delete", "policies", List.of("accountants")));
        assertThat(mixed.status()).as(mixed.toString()).isEqualTo(201);
        assertThat(mixed.json().path("type").asText()).isEqualTo("SCOPE");

        assertThat(evaluate(admin, base, "delete")).isTrue();
        assertThat(evaluate(admin, base, "read")).as("a scope permission on delete must not grant read").isFalse();
        assertThat(evaluate(admin, base, null)).as("nor the whole resource").isFalse();
    }

    private static boolean evaluate(final E2eAdminSession admin, final String base, final String scope) {
        final Map<String, Object> body = new java.util.HashMap<>(Map.of("roles", List.of("accountant"), "resourceName", "invoice"));
        if (scope != null) {
            body.put("scopeName", scope);
        }
        final E2eHttp.Response r = admin.post(base + "/evaluate", body);
        assertThat(r.status()).as(r.toString()).isEqualTo(200);
        return r.json().path("granted").asBoolean();
    }
}
