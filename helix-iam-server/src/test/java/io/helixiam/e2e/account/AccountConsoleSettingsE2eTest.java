/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.account;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.helixiam.e2e.AbstractE2eTest;
import io.helixiam.e2e.E2eAdminSession;
import io.helixiam.e2e.E2eHttp;
import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * B1: the realm settings that decide what the account console allows — authenticator removal, data export and
 * account deletion — through the admin API and the realm export / import.
 */
class AccountConsoleSettingsE2eTest extends AbstractE2eTest {

    @Test
    void defaults_allowRemovalAndExport_butNotDeletion() {
        final String realm = E2eSeed.unique("acs");
        seed().realm(realm);
        final E2eHttp.Response r = adminSession().get("/admin/realms/" + realm + "/settings/account-console");
        assertThat(r.status()).as(r.toString()).isEqualTo(200);
        assertThat(r.json().path("allowAuthenticatorRemoval").asBoolean()).isTrue();
        assertThat(r.json().path("allowDataExport").asBoolean()).isTrue();
        assertThat(r.json().path("allowAccountDeletion").asBoolean()).isFalse();
    }

    @Test
    void put_storesTheSettings_andAMissingFieldTakesItsDefault() {
        final String realm = E2eSeed.unique("acs");
        seed().realm(realm);
        final E2eAdminSession admin = adminSession();
        final String path = "/admin/realms/" + realm + "/settings/account-console";

        final E2eHttp.Response put = admin.put(path, Map.of("allowAuthenticatorRemoval", false, "allowAccountDeletion", true));
        assertThat(put.status()).as(put.toString()).isEqualTo(200);
        final JsonNode got = admin.get(path).json();
        assertThat(got.path("allowAuthenticatorRemoval").asBoolean()).isFalse();
        assertThat(got.path("allowDataExport").asBoolean()).as("left out: default").isTrue();
        assertThat(got.path("allowAccountDeletion").asBoolean()).isTrue();

        assertThat(admin.get("/admin/realms/" + E2eSeed.unique("nope") + "/settings/account-console").status())
                .isEqualTo(404);
    }

    @Test
    void theSettings_travelWithTheRealmExport_andImport() {
        final String source = E2eSeed.unique("acs-src");
        seed().realm(source);
        final E2eAdminSession admin = adminSession();
        admin.put("/admin/realms/" + source + "/settings/account-console",
                Map.of("allowAuthenticatorRemoval", false, "allowDataExport", false, "allowAccountDeletion", true));

        final ObjectNode doc = (ObjectNode) admin.get("/admin/realms/" + source + "/export").json();
        assertThat(doc.path("accountConsole").path("allowAccountDeletion").asBoolean()).isTrue();
        assertThat(doc.path("accountConsole").path("allowDataExport").asBoolean()).isFalse();

        final String target = E2eSeed.unique("acs-dst");
        final E2eHttp.Response imported = admin.post("/admin/realms/" + target + "/import", doc);
        assertThat(imported.status()).as(imported.toString()).isEqualTo(200);
        assertThat(imported.json().has("failed")).as(imported.toString()).isFalse();
        final JsonNode got = admin.get("/admin/realms/" + target + "/settings/account-console").json();
        assertThat(got.path("allowAuthenticatorRemoval").asBoolean()).isFalse();
        assertThat(got.path("allowDataExport").asBoolean()).isFalse();
        assertThat(got.path("allowAccountDeletion").asBoolean()).isTrue();
    }
}
