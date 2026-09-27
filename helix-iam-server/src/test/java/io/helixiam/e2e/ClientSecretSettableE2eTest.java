/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * C2: a client secret can be set by the caller (a secrets manager is the source of truth) on create, update and
 * import, and through {@code POST /admin/realms/{r}/clients/{id}/secret} with {@code {"secret": "..."}}. The
 * secret is stored like a generated one (the token endpoint accepts it), is at least 32 characters, and is never
 * echoed back or exported.
 */
class ClientSecretSettableE2eTest extends AbstractE2eTest {

    private static final String SECRET_A = "a-secret-from-the-vault-0123456789abcdef";
    private static final String SECRET_B = "b-secret-from-the-vault-0123456789abcdef";

    @Test
    void createWithASecret_storesItAndNeverReturnsIt() {
        final String realm = E2eSeed.unique("sec");
        seed().realm(realm);
        final E2eAdminSession admin = adminSession();
        final String clientId = E2eSeed.unique("svc");

        final E2eHttp.Response created = admin.post("/admin/realms/" + realm + "/clients",
                Map.of("clientId", clientId, "grantTypes", List.of("client_credentials"), "clientSecret", SECRET_A));
        assertThat(created.status()).as(created.toString()).isEqualTo(201);
        assertThat(created.body()).doesNotContain(SECRET_A);
        assertThat(created.json().path("secret").isNull() || created.json().path("secret").isMissingNode()).isTrue();

        assertThat(oidc(realm).clientCredentials(clientId, SECRET_A, null).accessToken()).isNotBlank();
    }

    @Test
    void aShortSecret_isA400WithAFieldError() {
        final String realm = E2eSeed.unique("sec");
        seed().realm(realm);
        final E2eAdminSession admin = adminSession();
        final E2eHttp.Response r = admin.post("/admin/realms/" + realm + "/clients",
                Map.of("clientId", E2eSeed.unique("svc"), "grantTypes", List.of("client_credentials"),
                        "clientSecret", "too-short"));
        assertThat(r.status()).as(r.toString()).isEqualTo(400);
        assertThat(r.json().path("fieldErrors").has("clientSecret")).as(r.toString()).isTrue();
        assertThat(r.body()).doesNotContain("too-short");
    }

    @Test
    void updateWithASecret_replacesIt_andUpdateWithoutOneKeepsIt() {
        final String realm = E2eSeed.unique("sec");
        seed().realm(realm);
        final E2eAdminSession admin = adminSession();
        final String clientId = E2eSeed.unique("svc");
        final String id = admin.post("/admin/realms/" + realm + "/clients", Map.of("clientId", clientId,
                "grantTypes", List.of("client_credentials"), "clientSecret", SECRET_A)).json().path("id").asText();

        final E2eHttp.Response updated = admin.put("/admin/realms/" + realm + "/clients/" + id,
                Map.of("clientId", clientId, "grantTypes", List.of("client_credentials"), "clientSecret", SECRET_B));
        assertThat(updated.status()).as(updated.toString()).isEqualTo(200);
        assertThat(updated.body()).doesNotContain(SECRET_B);
        assertThat(oidc(realm).tokenEndpoint(clientId, SECRET_A, Map.of("grant_type", "client_credentials")).status())
                .isEqualTo(401);
        assertThat(oidc(realm).clientCredentials(clientId, SECRET_B, null).accessToken()).isNotBlank();

        final E2eHttp.Response plain = admin.put("/admin/realms/" + realm + "/clients/" + id,
                Map.of("clientId", clientId, "grantTypes", List.of("client_credentials")));
        assertThat(plain.status()).as(plain.toString()).isEqualTo(200);
        assertThat(oidc(realm).clientCredentials(clientId, SECRET_B, null).accessToken()).isNotBlank();
    }

    @Test
    void postSecret_setsTheGivenSecret_withoutReturningIt() {
        final String realm = E2eSeed.unique("sec");
        seed().realm(realm);
        final E2eSeed.SeededClient sa = seed().serviceAccountClient(realm, E2eSeed.unique("svc"), List.of("openid"));
        final E2eAdminSession admin = adminSession();
        final String path = "/admin/realms/" + realm + "/clients/" + sa.id() + "/secret";

        final E2eHttp.Response set = admin.post(path, Map.of("secret", SECRET_A));
        assertThat(set.status()).as(set.toString()).isEqualTo(204);
        assertThat(set.body() == null ? "" : set.body()).doesNotContain(SECRET_A);
        assertThat(oidc(realm).tokenEndpoint(sa.clientId(), sa.secret(), Map.of("grant_type", "client_credentials"))
                .status()).isEqualTo(401);
        assertThat(oidc(realm).clientCredentials(sa.clientId(), SECRET_A, null).accessToken()).isNotBlank();

        final E2eHttp.Response tooShort = admin.post(path, Map.of("secret", "short"));
        assertThat(tooShort.status()).as(tooShort.toString()).isEqualTo(400);
        assertThat(tooShort.json().path("fieldErrors").has("secret")).isTrue();

        // Without a secret the endpoint still rotates to a generated secret (returned once), as before.
        final E2eHttp.Response rotated = admin.post(path, Map.of());
        assertThat(rotated.status()).as(rotated.toString()).isEqualTo(200);
        assertThat(rotated.json().path("secret").asText()).isNotBlank();
    }

    @Test
    void postSecret_onAnotherRealmsClient_is404() {
        final String home = E2eSeed.unique("sec");
        final String other = E2eSeed.unique("sec");
        seed().realm(home);
        seed().realm(other);
        final E2eSeed.SeededClient sa = seed().serviceAccountClient(home, E2eSeed.unique("svc"), List.of("openid"));
        final E2eHttp.Response r = adminSession().post("/admin/realms/" + other + "/clients/" + sa.id() + "/secret",
                Map.of("secret", SECRET_A));
        assertThat(r.status()).as(r.toString()).isEqualTo(404);
        assertThat(oidc(home).clientCredentials(sa.clientId(), sa.secret(), null).accessToken()).isNotBlank();
    }

    @Test
    void import_acceptsAClientSecret_andExportNeverCarriesIt() {
        final String realm = E2eSeed.unique("sec");
        seed().realm(realm);
        final E2eAdminSession admin = adminSession();
        final String clientId = E2eSeed.unique("svc");
        final ObjectMapper mapper = new ObjectMapper();
        final ObjectNode doc = (ObjectNode) admin.get("/admin/realms/" + realm + "/export").json();
        final ArrayNode clients = doc.putArray("clients");
        final Map<String, Object> client = new HashMap<>();
        client.put("clientId", clientId);
        client.put("grantTypes", List.of("client_credentials"));
        client.put("clientSecret", SECRET_A);
        clients.add(mapper.valueToTree(client));

        final E2eHttp.Response imported = admin.post("/admin/realms/" + realm + "/import", doc);
        assertThat(imported.status()).as(imported.toString()).isEqualTo(200);
        assertThat(imported.body()).doesNotContain(SECRET_A);
        assertThat(oidc(realm).clientCredentials(clientId, SECRET_A, null).accessToken()).isNotBlank();

        // Re-import with another secret updates it.
        ((ObjectNode) clients.get(0)).put("clientSecret", SECRET_B);
        assertThat(admin.post("/admin/realms/" + realm + "/import", doc).status()).isEqualTo(200);
        assertThat(oidc(realm).clientCredentials(clientId, SECRET_B, null).accessToken()).isNotBlank();

        final JsonNode export = admin.get("/admin/realms/" + realm + "/export").json();
        assertThat(export.toString()).doesNotContain(SECRET_A).doesNotContain(SECRET_B);

        // A short secret in an import is refused for that client (never stored), the rest of the import runs.
        ((ObjectNode) clients.get(0)).put("clientSecret", "short");
        final E2eHttp.Response bad = admin.post("/admin/realms/" + realm + "/import", doc);
        assertThat(bad.body()).doesNotContain("\"short\"");
        assertThat(oidc(realm).clientCredentials(clientId, SECRET_B, null).accessToken()).isNotBlank();
    }
}
