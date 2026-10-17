/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Security review H5 (final round): binding external trust to an admin service account — a workload-identity issuer,
 * an agent — is acting on that client and needs its admin permissions; redirecting a built-in sign-in client (the
 * console, the CLI) needs realm-admin; {@code manage-X} includes {@code view-X} when comparing permissions.
 */
class TrustBindingE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Trust-Binding-Passw0rd!";

    private String realm;
    private E2eAdminSession admin;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("trust");
        seed().realm(realm);
        admin = adminSession();
    }

    @Test
    void workloadIdentity_cannotBeBoundToAnAdminServiceAccount_belowRealmAdmin() {
        final E2eSeed.SeededClient adminSa = adminServiceAccount();
        final E2eSeed.SeededClient plain = seed().serviceAccountClient(realm, E2eSeed.unique("plain"), List.of("openid"));
        final E2eAdminSession mr = scoped("manage-realm");
        assertThat(mr.post(base() + "/workload-identity", wif(adminSa.clientId())).status()).isEqualTo(403);
        assertThat(mr.post(base() + "/workload-identity", wif(plain.clientId())).status()).isEqualTo(201);
        final E2eHttp.Response byAdmin = admin.post(base() + "/workload-identity", wif(adminSa.clientId()));
        assertThat(byAdmin.status()).isEqualTo(201);
        final String id = byAdmin.json().path("id").asText();
        // Re-pointing or deleting the admin's binding is acting on the admin service account too.
        assertThat(mr.put(base() + "/workload-identity/" + id, wif(plain.clientId())).status()).isEqualTo(403);
        assertThat(mr.delete(base() + "/workload-identity/" + id).status()).isEqualTo(403);

        // The import slice: a manage-realm import cannot bind it either.
        final E2eHttp.Response imported = mr.post(base() + "/import", Map.of("formatVersion", 2,
                "workloadIdentity", List.of(Map.of("name", E2eSeed.unique("imp"), "issuer", "https://ci.evil.example",
                        "subject", "repo:evil", "audience", "helix", "clientId", adminSa.clientId(), "enabled", true))));
        assertThat(imported.body()).as(imported.toString()).doesNotContain("\"created\":{\"workloadIdentity\"");
        final List<String> bound = new java.util.ArrayList<>();
        admin.get(base() + "/workload-identity").json().forEach(w -> bound.add(w.path("issuer").asText()));
        assertThat(bound).doesNotContain("https://ci.evil.example");
    }

    @Test
    void agents_cannotBindAnAdminServiceAccount_norCarryAdminRoles_belowRealmAdmin() {
        final E2eSeed.SeededClient adminSa = adminServiceAccount();
        final E2eSeed.SeededClient plain = seed().serviceAccountClient(realm, E2eSeed.unique("plain"), List.of("openid"));
        final E2eAdminSession mr = scoped("manage-realm");
        assertThat(mr.post(base() + "/agents", agent(adminSa.clientId(), null)).status()).isEqualTo(403);
        assertThat(mr.post(base() + "/agents", agent(plain.clientId(), "admin")).status()).isEqualTo(403);
        assertThat(mr.post(base() + "/agents", agent(plain.clientId(), null)).status()).isEqualTo(201);
        assertThat(admin.post(base() + "/agents", agent(adminSa.clientId(), null)).status()).isEqualTo(201);
    }

    @Test
    void manageClients_cannotRedirectTheBuiltInSignInClients_butEditsOrdinaryClients() {
        context.getBean(io.helixiam.authorization.service.client.ConsoleClientBootstrapService.class)
                .ensureConsoleClient(realm);
        context.getBean(io.helixiam.authorization.service.client.CliClientBootstrapService.class).ensureCliClient(realm);
        final E2eAdminSession mc = scoped("manage-clients");
        final JsonNode console = clientNamed("helix-console");
        final Map<String, Object> evil = body(console, "https://evil.example/cb");
        assertThat(mc.put(base() + "/clients/" + console.path("id").asText(), evil).status()).isEqualTo(403);
        final Map<String, Object> grants = body(console, null);
        grants.put("grantTypes", List.of("authorization_code", "refresh_token", "implicit"));
        assertThat(mc.put(base() + "/clients/" + console.path("id").asText(), grants).status()).isEqualTo(403);
        final Map<String, Object> pub = body(console, null);
        pub.put("publicClient", !console.path("publicClient").asBoolean());
        assertThat(mc.put(base() + "/clients/" + console.path("id").asText(), pub).status()).isEqualTo(403);
        // Harmless edits of the console client stay possible.
        final Map<String, Object> described = body(console, null);
        described.put("description", "Admin console");
        assertThat(mc.put(base() + "/clients/" + console.path("id").asText(), described).status()).isEqualTo(200);

        final E2eSeed.SeededClient plain = seed().confidentialClient(realm, E2eSeed.unique("app"), List.of("openid"));
        final JsonNode plainJson = admin.get(base() + "/clients/" + plain.id()).json();
        assertThat(mc.put(base() + "/clients/" + plain.id(), body(plainJson, "https://app.example/cb")).status())
                .isEqualTo(200);
        // A realm admin may change the console's sign-in settings.
        final JsonNode cli = clientNamed("helix-cli");
        assertThat(admin.put(base() + "/clients/" + cli.path("id").asText(), body(cli, "http://127.0.0.1:9/cb"))
                .status()).isEqualTo(200);
    }

    @Test
    void builtInSignInClients_allowOnlyCosmeticChangesBelowRealmAdmin_nullsCountAsChanges() {
        context.getBean(io.helixiam.authorization.service.client.ConsoleClientBootstrapService.class)
                .ensureConsoleClient(realm);
        final E2eAdminSession mc = scoped("manage-clients");
        final JsonNode console = clientNamed("helix-console");
        final String path = base() + "/clients/" + console.path("id").asText();
        // A request without redirectUris would store none (the writer treats null as empty): refused.
        final Map<String, Object> wipe = body(console, null);
        wipe.remove("redirectUris");
        assertThat(mc.put(path, wipe).status()).isEqualTo(403);
        for (final Map.Entry<String, Object> change : List.<Map.Entry<String, Object>>of(
                Map.entry("authFlowAlias", "custom-flow"), Map.entry("webOrigins", List.of("https://evil.example")),
                Map.entry("scopes", List.of("openid", "offline_access")), Map.entry("accessTokenLifespan", 86400),
                Map.entry("frontchannelLogoutUri", "https://evil.example/logout"),
                Map.entry("consentRequired", !console.path("consentRequired").asBoolean()),
                Map.entry("jarmResponseMode", "query.jwt"))) {
            final Map<String, Object> b = body(console, null);
            b.put(change.getKey(), change.getValue());
            assertThat(mc.put(path, b).status()).as(change.getKey()).isEqualTo(403);
        }
        final JsonNode after = admin.get(path).json();
        assertThat(after.path("redirectUris")).isEqualTo(console.path("redirectUris"));
        // Cosmetic fields are fine.
        final Map<String, Object> cosmetic = body(console, null);
        cosmetic.put("name", "Admin console");
        cosmetic.put("description", "Where admins sign in");
        assertThat(mc.put(path, cosmetic).status()).isEqualTo(200);
        // Client roles of the console need realm-admin too.
        assertThat(mc.post(base() + "/clients/helix-console/roles", Map.of("name", "evil")).status()).isEqualTo(403);
        assertThat(admin.post(base() + "/clients/helix-console/roles", Map.of("name", "ok")).status()).isIn(200, 201);
    }

    @Test
    void anAgentsAdminRoles_makeItsClientPrivileged_andGateItsTransitions() {
        final E2eSeed.SeededClient plain = seed().serviceAccountClient(realm, E2eSeed.unique("agentsvc"), List.of("openid"));
        final E2eHttp.Response created = admin.post(base() + "/agents", agent(plain.clientId(), "admin"));
        assertThat(created.status()).as(created.toString()).isEqualTo(201);
        final String agentId = created.json().path("id").asText();
        // The client's tokens carry the agent's admin role: its secret is off limits below realm-admin.
        assertThat(scoped("manage-clients").get(base() + "/clients/" + plain.id() + "/secret").status())
                .isEqualTo(403);
        assertThat(admin.post(base() + "/agents/" + agentId + "/suspend", Map.of()).status()).isEqualTo(200);
        final E2eAdminSession mr = scoped("manage-realm");
        assertThat(mr.post(base() + "/agents/" + agentId + "/activate", Map.of()).status()).isEqualTo(403);
        assertThat(scoped("manage-clients").post(base() + "/agents/" + agentId + "/activate", Map.of()).status())
                .isEqualTo(403);
        assertThat(admin.post(base() + "/agents/" + agentId + "/activate", Map.of()).status()).isEqualTo(200);
    }

    @Test
    void manageUsers_includesViewUsers_whenComparingPermissions() {
        final String viewer = admin.post(base() + "/roles", Map.of("name", "viewer")).json().path("roleId").asText();
        final String viewerId = viewer.isBlank() ? roleId("viewer") : viewer;
        assertThat(admin.put(base() + "/admin-roles/" + viewerId, Map.of("permissions", List.of("view-users"))).status())
                .isEqualTo(200);
        final E2eSeed.SeededUser target = seed().user(realm, E2eSeed.unique("t"), PASSWORD);
        assertThat(scoped("manage-users").post(base() + "/users/" + target.userId() + "/roles",
                Map.of("roleId", viewerId)).status()).isEqualTo(204);
    }

    // ------------------------------------------------------------------------------------------------ helpers

    private String base() {
        return "/admin/realms/" + realm;
    }

    private E2eSeed.SeededClient adminServiceAccount() {
        final E2eSeed.SeededClient sa = seed().serviceAccountClient(realm, E2eSeed.unique("adminsvc"), List.of("openid"));
        assertThat(admin.post(base() + "/clients/" + sa.clientId() + "/service-account/roles",
                Map.of("roleName", "admin", "roleType", "REALM")).status()).isEqualTo(201);
        return sa;
    }

    private static Map<String, Object> wif(final String clientId) {
        final Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", E2eSeed.unique("wif"));
        m.put("issuer", "https://ci.example");
        m.put("subject", "repo:example/app");
        m.put("audience", "helix");
        m.put("clientId", clientId);
        m.put("enabled", true);
        return m;
    }

    private static Map<String, Object> agent(final String clientId, final String roles) {
        final Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", E2eSeed.unique("agent"));
        m.put("owner", "owner@example.com");
        m.put("authMethod", "SECRET");
        m.put("clientId", clientId);
        if (roles != null) {
            m.put("roles", roles);
        }
        m.put("enabled", true);
        return m;
    }

    private JsonNode clientNamed(final String clientId) {
        for (final JsonNode c : admin.get(base() + "/clients").json()) {
            if (clientId.equals(c.path("clientId").asText())) {
                return c;
            }
        }
        throw new AssertionError("No client " + clientId + " in " + realm);
    }

    private static Map<String, Object> body(final JsonNode client, final String extraRedirect) {
        final Map<String, Object> out = new LinkedHashMap<>();
        client.properties().forEach(e -> {
            if (!List.of("realmId", "id", "secret").contains(e.getKey())) {
                out.put(e.getKey(), e.getValue());
            }
        });
        if (extraRedirect != null) {
            final List<String> uris = new java.util.ArrayList<>();
            client.path("redirectUris").forEach(u -> uris.add(u.asText()));
            uris.add(extraRedirect);
            out.put("redirectUris", uris);
        }
        return out;
    }

    private String roleId(final String name) {
        for (final JsonNode r : admin.get(base() + "/roles").json()) {
            if (name.equals(r.path("name").asText())) {
                return r.path("roleId").asText();
            }
        }
        throw new AssertionError("No role " + name);
    }

    private E2eAdminSession scoped(final String permission) {
        final String roleName = E2eSeed.unique("tb-" + permission);
        String id = admin.post(base() + "/roles", Map.of("name", roleName)).json().path("roleId").asText();
        if (id.isBlank()) {
            id = roleId(roleName);
        }
        assertThat(admin.put(base() + "/admin-roles/" + id, Map.of("permissions", List.of(permission))).status())
                .isEqualTo(200);
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("tb-u"), PASSWORD);
        assertThat(admin.post(base() + "/users/" + user.userId() + "/roles", Map.of("roleId", id)).status())
                .isEqualTo(204);
        return E2eAdminSession.login(newBrowser(), realm, user.username(), PASSWORD);
    }
}
