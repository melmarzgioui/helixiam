/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Review rc.3 #5: a realm's own export re-imports cleanly (it failed on admin-role permissions); an import whose
 * realm cannot be written stops before anything else is written; an invalid realm id is a 400, not a 500; failure
 * reasons never carry database internals.
 */
class RealmImportE2eTest extends AbstractE2eTest {

    private final ObjectMapper json = new ObjectMapper();

    @Test
    void reimportingARealmsOwnExport_succeedsWithoutFailures() {
        final String realm = E2eSeed.unique("roundtrip");
        seed().realm(realm, "Round trip");
        seed().confidentialClient(realm, "web", List.of("openid"));
        final E2eAdminSession admin = adminSession();
        final JsonNode export = admin.get("/admin/realms/" + realm + "/export").json();
        assertThat(export.path("adminRoles").size()).as("the export carries admin-role grants").isPositive();

        final E2eHttp.Response again = admin.post("/admin/realms/" + realm + "/import", export);
        assertThat(again.status()).as(again.toString()).isEqualTo(200);
        assertThat(again.json().has("failed")).isFalse();
        final E2eHttp.Response twice = admin.post("/admin/realms/" + realm + "/import", export);
        assertThat(twice.status()).as(twice.toString()).isEqualTo(200);
    }

    @Test
    void whenTheRealmCannotBeWritten_nothingElseIsImported() {
        final String source = E2eSeed.unique("src");
        seed().realm(source, "Source");
        seed().confidentialClient(source, "portal", List.of("openid"));
        final E2eAdminSession admin = adminSession();
        final ObjectNode doc = (ObjectNode) admin.get("/admin/realms/" + source + "/export").json();
        ((ObjectNode) doc.path("realm")).put("displayName", "x".repeat(5000)); // the realm write fails

        final String target = E2eSeed.unique("broken");
        final E2eHttp.Response r = admin.post("/admin/realms/" + target + "/import", doc);
        assertThat(r.status()).as(r.toString()).isEqualTo(422);
        assertThat(r.json().path("slices").path("realm").path("failed").asInt()).isEqualTo(1);
        assertThat(r.json().path("slices").has("clients")).as("no other slice ran").isFalse();
        assertThat(admin.get("/admin/realms/" + target + "/clients").json().toString()).doesNotContain("\"portal\"");
        assertThat(r.body()).doesNotContain("could not execute statement").doesNotContain("value too long");
    }

    @Test
    void anInvalidRealmId_isRejectedWith400() {
        final E2eHttp.Response r = adminSession().post("/admin/realms/" + "r".repeat(300) + "/import",
                json.createObjectNode().put("version", 1));
        assertThat(r.status()).as(r.toString()).isEqualTo(400);
        final E2eHttp.Response settings = adminSession().put("/admin/realms/Bad%20Realm%21/settings", Map.of(
                "displayName", "x", "accessTokenTtlSeconds", 300, "refreshTokenTtlSeconds", 86400, "enabled", true,
                "passwordMinLength", 12));
        assertThat(settings.status()).as(settings.toString()).isEqualTo(400);
    }
}
