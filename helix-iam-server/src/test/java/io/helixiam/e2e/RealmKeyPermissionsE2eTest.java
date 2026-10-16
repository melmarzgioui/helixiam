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

    @Test
    void encodedCasedAndMatrixPathTricks_neverReachAWriteWithALowerPermission() {
        final String realm = E2eSeed.unique("keytrick");
        seed().realm(realm);
        oidc(realm).jwks();
        final E2eAdminSession admin = adminSession();
        final E2eAdminSession limited = scopedAdmin(admin, realm, "manage-realm");
        final String base = "/admin/realms/" + realm;
        // A valid import: a bypass would answer 201.
        final java.security.KeyPair kp = io.helixiam.testsupport.TestPki.rsa(2048);
        final Map<String, String> body = Map.of(
                "privateKeyPem", io.helixiam.testsupport.TestPki.pkcs8(kp.getPrivate()),
                "certificateChainPem", io.helixiam.testsupport.TestPki.pem(
                        io.helixiam.testsupport.TestPki.selfSigned(kp, "CN=trick", 30)));
        final String token = xsrf(limited, base + "/keys");

        for (final String trick : List.of("/k%65ys/import", "/%6Beys/import", "/KEYS/import", "/keys;x=1/import",
                "/keys/import/", "//keys/import", "/./keys/import", "/keys/./import", "/k%2565ys/import")) {
            final E2eHttp.Response r = limited.http().sendJson("POST", baseUrl() + base + trick, body,
                    "X-XSRF-TOKEN", token, "Accept", "application/json");
            assertThat(r.status()).as(trick + " → " + r).isIn(400, 403, 404, 405);
            assertThat(r.body()).as(trick).doesNotContain("\"keyId\"");
        }
        // users / clients: the same tricks resolve to (at least) the right permission, never manage-realm's.
        for (final String trick : List.of("/u%73ers", "/USERS", "/users;x=1", "/cl%69ents", "/Clients", "//clients")) {
            final E2eHttp.Response r = limited.http().sendJson("POST", baseUrl() + base + trick,
                    Map.of("username", E2eSeed.unique("x"), "clientId", E2eSeed.unique("c")),
                    "X-XSRF-TOKEN", token, "Accept", "application/json");
            assertThat(r.status()).as(trick + " → " + r).isIn(400, 403, 404, 405);
        }
        // The plain routes still answer as their permission says.
        assertThat(limited.post(base + "/users", Map.of("username", E2eSeed.unique("x"))).status()).isEqualTo(403);
        assertThat(admin.get(keys(realm)).json().size()).isEqualTo(1);
        // A legitimately encoded id deeper in the path is not refused by the encoding filter.
        assertThat(admin.get(base + "/saml-clients/urn%3Aexample%3Asp").status()).isNotEqualTo(400);
    }

    private static String xsrf(final E2eAdminSession session, final String path) {
        session.get(path);
        return session.http().cookieFor("XSRF-TOKEN", path).orElseThrow();
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
