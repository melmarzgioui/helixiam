/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import io.helixiam.authorization.domain.federation.LinkProvenance;
import io.helixiam.authorization.service.federation.FederatedLinkService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Security review round 6: every write that changes how an administrator signs in, which tokens they get, or what
 * trusts them is refused to a lower admin (403) and allowed to a realm admin of the realm (2xx), through the REST API
 * and through realm import. One test per row of the design doc's inventory that has a guard.
 */
class SignInSurfaceE2eTest extends AbstractE2eTest {

    static {
        System.setProperty("helix.egress.allow-private", "true");
        System.setProperty("helix.egress.allowed-private-hosts", "127.0.0.1");
    }

    private static final String PASSWORD = "SignIn-Surface-Passw0rd!";

    private String realm;
    private E2eAdminSession admin;
    private String adminRoleId;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("surface");
        seed().realm(realm);
        admin = adminSession();
        adminRoleId = roleId("admin");
    }

    // ------------------------------------------------------------------------------------- identity providers

    @Test
    void identityProviderLinkedToAnAdminNeedsTheirPermissions() {
        final E2eSeed.SeededUser victim = realmAdminUser();
        assertThat(admin.post(base() + "/identity-providers", idp("corp", corp("https://corp.example"))).status())
                .isEqualTo(201);
        context.getBean(FederatedLinkService.class).link("corp", "victim-sub", victim.userId(), LinkProvenance.JIT);
        assertThat(admin.post(base() + "/identity-providers", idp("other", corp("https://other.example"))).status())
                .isEqualTo(201);

        final E2eAdminSession mi = scoped("manage-identity-providers");
        assertThat(mi.put(base() + "/identity-providers/corp", idp("corp", corp("https://evil.example"))).status())
                .isEqualTo(403);
        assertThat(mi.delete(base() + "/identity-providers/corp").status()).isEqualTo(403);
        // An identity provider no administrator signs in through stays open to identity-provider managers.
        assertThat(mi.put(base() + "/identity-providers/other", idp("other", corp("https://other2.example"))).status())
                .isEqualTo(200);
        // Import is the same service.
        final E2eAdminSession mr = scoped("manage-realm");
        mr.post(base() + "/import", Map.of("formatVersion", 2, "identityProviders",
                List.of(idp("corp", corp("https://evil.example")))));
        assertThat(admin.get(base() + "/identity-providers/corp").json().path("config").path("issuer").asText())
                .isEqualTo("https://corp.example");

        final E2eAdminSession ra = realmAdmin();
        assertThat(ra.put(base() + "/identity-providers/corp", idp("corp", corp("https://corp2.example"))).status())
                .isEqualTo(200);
        assertThat(ra.delete(base() + "/identity-providers/corp").status()).isEqualTo(204);
    }

    @Test
    void anAdministratorSignsInThroughALinkOnlyWhenTheyMadeIt() throws Exception {
        final E2eSeed.SeededUser victim = realmAdminUser();
        final RSAKey key = new RSAKeyGenerator(2048).keyID("k1").generate();
        final String jwks = new JWKSet(key.toPublicJWK()).toString();
        final AtomicReference<String> nonce = new AtomicReference<>();
        final HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        final String issuer = "http://127.0.0.1:" + server.getAddress().getPort();
        server.createContext("/jwks", ex -> respond(ex, jwks));
        server.createContext("/token", ex -> {
            try {
                final SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("k1").build(),
                        new JWTClaimsSet.Builder().issuer(issuer).subject("victim-sub").audience("helix")
                                .claim("nonce", nonce.get()).issueTime(new Date())
                                .expirationTime(new Date(System.currentTimeMillis() + 300_000)).build());
                jwt.sign(new RSASSASigner(key));
                respond(ex, "{\"id_token\":\"" + jwt.serialize() + "\",\"access_token\":\"a\",\"token_type\":\"Bearer\"}");
            } catch (final Exception e) {
                respond(ex, "{}");
            }
        });
        server.start();
        permissiveTokenClient();
        try {
            assertThat(admin.post(base() + "/identity-providers", idp("corp", corp(issuer))).status()).isEqualTo(201);
            Thread.sleep(1500);
            final FederatedLinkService links = context.getBean(FederatedLinkService.class);

            // A link made by matching an e-mail address (or of unknown origin) never signs in an administrator.
            links.link("corp", "victim-sub", victim.userId(), LinkProvenance.AUTO);
            assertThat(brokerLogin(nonce).get(base() + "/admin-roles", "Accept", "application/json").status())
                    .isNotEqualTo(200);

            // A link the administrator made themselves (here: the sign-in that created the account) does.
            links.link("corp", "victim-sub", victim.userId(), LinkProvenance.JIT);
            assertThat(brokerLogin(nonce).get(base() + "/admin-roles", "Accept", "application/json").status())
                    .isEqualTo(200);
        } finally {
            server.stop(0);
        }
    }

    // ------------------------------------------------------------------------------------- applications

    @Test
    void theApplicationOfASignInClientNeedsRealmAdmin() {
        bootstrapSignInClients();
        context.getBean(io.helixiam.authorization.service.application.ApplicationBackfillRunner.class).run(null);
        admin.post(base() + "/flows", Map.of("alias", "partner-flow", "copyFromAlias", "browser"));
        final String appName = appOf("helix-console");
        final String appPath = base() + "/applications/" + enc(appName);
        final JsonNode app = admin.get(appPath).json();

        final E2eAdminSession mc = scoped("manage-clients");
        final Map<String, Object> flow = appBody(app);
        flow.put("authFlowAlias", "partner-flow");
        assertThat(mc.put(appPath, flow).status()).isEqualTo(403);
        final Map<String, Object> off = appBody(app);
        off.put("enabled", false);
        assertThat(mc.put(appPath, off).status()).isEqualTo(403);
        assertThat(mc.delete(appPath).status()).isEqualTo(403);
        final Map<String, Object> cosmetic = appBody(app);
        cosmetic.put("displayName", "Admin console");
        cosmetic.put("description", "Where administrators work");
        assertThat(mc.put(appPath, cosmetic).status()).isEqualTo(200);

        scoped("manage-realm").post(base() + "/import", Map.of("formatVersion", 2, "applications",
                List.of(Map.of("name", appName, "authFlowAlias", "partner-flow", "enabled", true))));
        assertThat(admin.get(appPath).json().path("authFlowAlias").asText(""))
                .isEqualTo(app.path("authFlowAlias").asText(""));

        final E2eAdminSession ra = realmAdmin();
        assertThat(ra.put(appPath, flow).status()).isEqualTo(200);
        assertThat(ra.delete(appPath).status()).isEqualTo(204);
    }

    // ------------------------------------------------------------------------------------- sign-in clients

    @Test
    void onlyARealmAdminCreatesABuiltInSignInClient() {
        bootstrapSignInClients();
        final E2eAdminSession ra = realmAdmin();
        // A realm from before 1.0 that never got helix-cli (the built-in clients cannot be deleted over the API).
        final var clients = context.getBean(io.helixiam.authorization.repository.ServiceProviderRepository.class);
        clients.findByClientIdAndRealmIdAndDeleted("helix-cli", realm, false).ifPresent(clients::delete);

        final Map<String, Object> squat = new LinkedHashMap<>();
        squat.put("clientId", "helix-cli");
        squat.put("name", "HelixIAM CLI");
        squat.put("publicClient", true);
        squat.put("grantTypes", List.of("authorization_code", "refresh_token"));
        squat.put("redirectUris", List.of("https://evil.example/cb"));
        squat.put("scopes", List.of("openid"));
        assertThat(scoped("manage-clients").post(base() + "/clients", squat).status()).isEqualTo(403);
        assertThat(hasClient("helix-cli")).isFalse();

        assertThat(ra.post(base() + "/clients", squat).status()).isBetween(200, 201);
        // Every start resets where the CLI's codes go, whoever made the client.
        context.getBean(io.helixiam.authorization.service.client.CliClientBootstrapService.class).ensureCliClient(realm);
        final List<String> redirects = new ArrayList<>();
        clientNamed("helix-cli").path("redirectUris").forEach(n -> redirects.add(n.asText()));
        assertThat(redirects).doesNotContain("https://evil.example/cb").contains("http://127.0.0.1/callback");
    }

    @Test
    void theMappersAndResourcesOfASignInClientNeedRealmAdmin() {
        bootstrapSignInClients();
        final Map<String, Object> mapper = Map.of("name", "x", "mapperType", "user-attribute", "source", "email",
                "claimName", "x_mail", "addToAccessToken", true, "addToIdToken", true);
        assertThat(scoped("manage-clients").post(base() + "/clients/helix-console/mappers", mapper).status())
                .isEqualTo(403);
        final E2eAdminSession mr = scoped("manage-realm");
        mr.post(base() + "/import", Map.of("formatVersion", 2, "clientProtocolMappers",
                List.of(Map.of("clientId", "helix-console", "name", "imp", "mapperType", "user-attribute",
                        "source", "email", "claimName", "x_imp", "addToAccessToken", true, "addToIdToken", true))));
        assertThat(admin.get(base() + "/clients/helix-console/mappers").body()).doesNotContain("x_imp");
        mr.post(base() + "/import", Map.of("formatVersion", 2, "resourceIndicators",
                List.of(Map.of("clientId", "helix-console", "resources", List.of("https://evil.example")))));
        assertThat(context.getBean(io.helixiam.authorization.service.resource.ResourceIndicatorService.class)
                .resolveAllowedResourcesForClient(realm, "helix-console")).doesNotContain("https://evil.example");

        final E2eAdminSession ra = realmAdmin();
        assertThat(ra.post(base() + "/clients/helix-console/mappers", mapper).status()).isBetween(200, 201);
        assertThat(ra.put(base() + "/clients/helix-console/allowed-resources",
                Map.of("resources", List.of("https://api.example"))).status()).isBetween(200, 204);
    }

    // ------------------------------------------------------------------------------------- flows

    @Test
    void theFlowsAdministratorsSignInThroughNeedRealmAdmin() {
        bootstrapSignInClients();
        final Map<String, Object> browser = Map.of("executions",
                admin.get(base() + "/flows/browser").json().path("executions"));
        final E2eAdminSession ma = scoped("manage-authorization");
        assertThat(ma.put(base() + "/flows/browser", browser).status()).isEqualTo(403);
        assertThat(scoped("manage-realm").put(base() + "/flow", browser).status()).isEqualTo(403);

        // A flow bound to the console (bound by a realm admin) is protected too, under its old and new name.
        admin.post(base() + "/flows", Map.of("alias", "console-flow", "copyFromAlias", "browser"));
        final JsonNode console = clientNamed("helix-console");
        final Map<String, Object> bound = body(console);
        bound.put("authFlowAlias", "console-flow");
        assertThat(admin.put(base() + "/clients/" + console.path("id").asText(), bound).status()).isEqualTo(200);
        assertThat(ma.put(base() + "/flows/console-flow", browser).status()).isEqualTo(403);
        assertThat(ma.patch(base() + "/flows/console-flow", Map.of("alias", "renamed")).status()).isEqualTo(403);
        assertThat(ma.delete(base() + "/flows/console-flow").status()).isEqualTo(403);
        admin.post(base() + "/flows", Map.of("alias", "spare", "copyFromAlias", "browser"));
        assertThat(ma.patch(base() + "/flows/spare", Map.of("alias", "browser")).status()).isNotEqualTo(200);

        // Other flows stay open to manage-authorization.
        assertThat(ma.post(base() + "/flows", Map.of("alias", "partner", "copyFromAlias", "browser")).status())
                .isEqualTo(200);
        assertThat(ma.put(base() + "/flows/partner", browser).status()).isEqualTo(200);

        final E2eAdminSession ra = realmAdmin();
        assertThat(ra.put(base() + "/flows/browser", browser).status()).isEqualTo(200);
        assertThat(ra.put(base() + "/flows/console-flow", browser).status()).isEqualTo(200);
    }

    // ------------------------------------------------------------------------------------- routes

    @Test
    void manageIncludesViewOnRoutes() {
        assertThat(scoped("manage-clients").get(base() + "/clients").status()).isEqualTo(200);
        assertThat(scoped("manage-users").get(base() + "/users").status()).isEqualTo(200);
        assertThat(scoped("manage-identity-providers").get(base() + "/trusted-lists").status()).isEqualTo(200);
        assertThat(scoped("manage-events").get(base() + "/sessions").status()).isEqualTo(200);
    }

    // ------------------------------------------------------------------------------------- credential delivery

    @Test
    void aPushDeviceForAnAdminNeedsTheirPermissions() {
        final E2eSeed.SeededUser victim = realmAdminUser();
        final E2eSeed.SeededUser plain = seed().user(realm, E2eSeed.unique("plain"), PASSWORD);
        final E2eAdminSession mr = scoped("manage-realm");
        assertThat(mr.post(base() + "/messaging/push-tokens", push(victim.userId())).status()).isEqualTo(403);
        assertThat(mr.post(base() + "/messaging/push-tokens", push(plain.userId())).status()).isBetween(200, 201);
        assertThat(realmAdmin().post(base() + "/messaging/push-tokens", push(victim.userId())).status())
                .isBetween(200, 201);
    }

    @Test
    void messagingProvidersAndTemplatesNeedRealmAdmin() {
        final Map<String, Object> provider = Map.of("channel", "EMAIL", "driver", "HTTP", "enabled", true,
                "fromAddress", "no-reply@surface.example", "config",
                Map.of("url", io.helixiam.e2e.browser.MailSink.get().url()));
        final Map<String, Object> template = new LinkedHashMap<>();
        template.put("templateKey", "password-reset");
        template.put("channel", "EMAIL");
        template.put("subject", "Reset");
        template.put("body", "Surface-marker {{code}}");
        template.put("enabled", true);
        final E2eAdminSession mr = scoped("manage-realm");
        assertThat(mr.put(base() + "/messaging/providers", provider).status()).isEqualTo(403);
        assertThat(mr.put(base() + "/messaging/templates", template).status()).isEqualTo(403);
        mr.post(base() + "/import", Map.of("formatVersion", 2, "messageTemplates", List.of(template)));
        assertThat(admin.get(base() + "/messaging/templates").body()).doesNotContain("Surface-marker");

        final E2eAdminSession ra = realmAdmin();
        assertThat(ra.put(base() + "/messaging/providers", provider).status()).isEqualTo(200);
        assertThat(mr.delete(base() + "/messaging/providers/EMAIL/HTTP").status()).isEqualTo(403);
        assertThat(ra.put(base() + "/messaging/templates", template).status()).isEqualTo(200);
        assertThat(ra.delete(base() + "/messaging/providers/EMAIL/HTTP").status()).isBetween(200, 204);
    }

    // ------------------------------------------------------------------------------------- realm sign-in policy

    @Test
    void theRealmsSignInPolicyNeedsRealmAdmin() {
        final E2eAdminSession mr = scoped("manage-realm");
        assertThat(mr.put(base() + "/settings/mfa", Map.of("skipGraceDays", 3)).status()).isEqualTo(403);
        assertThat(mr.put(base() + "/settings/magic-link", Map.of("enabled", true)).status()).isEqualTo(403);
        final JsonNode settings = admin.get(base() + "/settings").json();
        final Map<String, Object> lockout = body(settings);
        lockout.put("maxLoginFailures", settings.path("maxLoginFailures").asInt() + 7);
        assertThat(mr.put(base() + "/settings", lockout).status()).isEqualTo(403);
        final Map<String, Object> renamed = body(settings);
        renamed.put("displayName", "Surface realm");
        assertThat(mr.put(base() + "/settings", renamed).status()).isEqualTo(200);
        final String subject = admin.get(base() + "/subject-claim").json().path("claimKey").asText("sub");
        final String other = "email".equals(subject) ? "sub" : "email";
        assertThat(mr.put(base() + "/subject-claim", Map.of("claimKey", other)).status()).isEqualTo(403);

        final E2eAdminSession ra = realmAdmin();
        assertThat(ra.put(base() + "/settings/mfa", Map.of("skipGraceDays", 3)).status()).isEqualTo(200);
        assertThat(ra.put(base() + "/settings/magic-link", Map.of("enabled", true)).status()).isEqualTo(200);
        assertThat(ra.put(base() + "/settings/magic-link", Map.of("enabled", false)).status()).isEqualTo(200);
        assertThat(ra.put(base() + "/settings", lockout).status()).isEqualTo(200);
        assertThat(ra.put(base() + "/subject-claim", Map.of("claimKey", other)).status()).isEqualTo(200);
        assertThat(ra.put(base() + "/subject-claim", Map.of("claimKey", subject)).status()).isEqualTo(200);
    }

    // ------------------------------------------------------------------------------------- groups and roles

    @Test
    void deletingOrMovingWhatGrantsAdminPermissionsNeedsThem() {
        final String admins = admin.post(base() + "/groups", Map.of("name", E2eSeed.unique("admins"))).json()
                .path("groupId").asText();
        assertThat(admin.put(base() + "/groups/" + admins + "/roles/" + adminRoleId, Map.of()).status()).isEqualTo(204);
        final String plainGroup = admin.post(base() + "/groups", Map.of("name", E2eSeed.unique("plain"))).json()
                .path("groupId").asText();
        final E2eAdminSession mo = scoped("manage-organizations");
        assertThat(mo.delete(base() + "/groups/" + admins).status()).isEqualTo(403);
        assertThat(mo.put(base() + "/groups/" + plainGroup, Map.of("name", "moved", "parentId", admins)).status())
                .isEqualTo(403);
        assertThat(mo.put(base() + "/groups/" + plainGroup, Map.of("name", "renamed")).status()).isEqualTo(200);

        final String helper = admin.post(base() + "/roles", Map.of("name", E2eSeed.unique("helper"))).json()
                .path("roleId").asText();
        admin.put(base() + "/admin-roles/" + helper, Map.of("permissions", List.of("manage-users")));
        final String noGrants = admin.post(base() + "/roles", Map.of("name", E2eSeed.unique("plain-role"))).json()
                .path("roleId").asText();
        final E2eAdminSession mrol = scoped("manage-roles");
        assertThat(mrol.delete(base() + "/roles/" + helper).status()).isEqualTo(403);
        assertThat(mrol.delete(base() + "/roles/" + noGrants).status()).isBetween(200, 204);

        final E2eAdminSession ra = realmAdmin();
        assertThat(ra.put(base() + "/groups/" + plainGroup, Map.of("name", "moved", "parentId", admins)).status())
                .isEqualTo(200);
        assertThat(ra.delete(base() + "/groups/" + admins).status()).isBetween(200, 204);
        assertThat(ra.delete(base() + "/roles/" + helper).status()).isBetween(200, 204);
    }

    // ------------------------------------------------------------------------------------- helpers

    private E2eHttp brokerLogin(final AtomicReference<String> nonce) {
        final E2eHttp browser = newBrowser();
        final E2eHttp.Response start = browser.get("/realms/" + realm + "/broker/corp");
        final Map<String, String> q = OidcFlow.query(java.net.URI.create(start.header("Location").orElse("")));
        nonce.set(q.get("nonce"));
        final E2eHttp.Response cb = browser.get("/realms/" + realm + "/broker/corp/callback?code=x&state="
                + enc(q.get("state")));
        browser.followRedirects(cb);
        return browser;
    }

    /** Test seam only: let the broker's token client reach the loopback stub identity provider. */
    private void permissiveTokenClient() throws Exception {
        final Object bean = context.getBean(io.helixiam.authorization.federation.oidc.OidcTokenClient.class);
        final Object permissive = new io.helixiam.authorization.federation.oidc.HttpOidcTokenClient(
                io.helixiam.common.net.OutboundUrlGuard.permissive());
        for (final String fn : List.of("http", "jwksRetriever")) {
            final java.lang.reflect.Field f =
                    io.helixiam.authorization.federation.oidc.HttpOidcTokenClient.class.getDeclaredField(fn);
            f.setAccessible(true);
            f.set(bean, f.get(permissive));
        }
    }

    private void bootstrapSignInClients() {
        context.getBean(io.helixiam.authorization.service.client.ConsoleClientBootstrapService.class)
                .ensureConsoleClient(realm);
        context.getBean(io.helixiam.authorization.service.client.CliClientBootstrapService.class).ensureCliClient(realm);
    }

    private String appOf(final String clientId) {
        final String appId = clientNamed(clientId).path("applicationId").asText();
        assertThat(appId).as("the backfill gives %s an application", clientId).isNotBlank();
        return appId.substring(appId.indexOf('|') + 1);
    }

    private static Map<String, Object> appBody(final JsonNode app) {
        final Map<String, Object> out = new LinkedHashMap<>();
        out.put("name", app.path("name").asText());
        out.put("displayName", app.path("displayName").isNull() ? null : app.path("displayName").asText(null));
        out.put("description", app.path("description").isNull() ? null : app.path("description").asText(null));
        out.put("subjectClaim", app.path("subjectClaim").isNull() ? null : app.path("subjectClaim").asText(null));
        out.put("authFlowAlias", app.path("authFlowAlias").isNull() ? null : app.path("authFlowAlias").asText(null));
        out.put("enabled", app.path("enabled").asBoolean(true));
        return out;
    }

    private static Map<String, Object> push(final String userId) {
        return Map.of("userId", userId, "platform", "FCM", "token", E2eSeed.unique("device-token"));
    }

    private static Map<String, String> corp(final String issuer) {
        final Map<String, String> c = new LinkedHashMap<>();
        c.put("clientId", "helix");
        c.put("clientSecret", "corp-secret-0123456789");
        c.put("issuer", issuer);
        c.put("authorizationEndpoint", issuer + "/authorize");
        c.put("tokenEndpoint", issuer + "/token");
        c.put("jwksUri", issuer + "/jwks");
        return c;
    }

    private static Map<String, Object> idp(final String alias, final Map<String, String> config) {
        final Map<String, Object> m = new LinkedHashMap<>();
        m.put("alias", alias);
        m.put("protocol", "oidc");
        m.put("displayName", alias);
        m.put("enabled", true);
        m.put("config", config);
        return m;
    }

    private static void respond(final com.sun.net.httpserver.HttpExchange ex, final String body) throws java.io.IOException {
        final byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(200, b.length);
        ex.getResponseBody().write(b);
        ex.close();
    }

    private static String enc(final String s) {
        return java.net.URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private boolean hasClient(final String clientId) {
        for (final JsonNode c : admin.get(base() + "/clients").json()) {
            if (clientId.equals(c.path("clientId").asText())) {
                return true;
            }
        }
        return false;
    }

    private JsonNode clientNamed(final String clientId) {
        for (final JsonNode c : admin.get(base() + "/clients").json()) {
            if (clientId.equals(c.path("clientId").asText())) {
                return admin.get(base() + "/clients/" + c.path("id").asText()).json();
            }
        }
        throw new AssertionError("No client " + clientId + " in " + realm);
    }

    private static Map<String, Object> body(final JsonNode node) {
        final Map<String, Object> out = new LinkedHashMap<>();
        node.properties().forEach(e -> {
            if (!List.of("realmId", "id", "secret").contains(e.getKey())) {
                out.put(e.getKey(), e.getValue());
            }
        });
        return out;
    }

    private String base() {
        return "/admin/realms/" + realm;
    }

    private String roleId(final String name) {
        for (final JsonNode r : admin.get(base() + "/roles").json()) {
            if (name.equals(r.path("name").asText())) {
                return r.path("roleId").asText();
            }
        }
        throw new AssertionError("No role " + name);
    }

    private E2eSeed.SeededUser realmAdminUser() {
        final E2eSeed.SeededUser u = seed().user(realm, E2eSeed.unique("radmin"), PASSWORD);
        assertThat(admin.post(base() + "/users/" + u.userId() + "/roles", Map.of("roleId", adminRoleId)).status())
                .isBetween(200, 204);
        return u;
    }

    /** A realm admin of this realm (role {@code admin}), not a master admin. */
    private E2eAdminSession realmAdmin() {
        final E2eSeed.SeededUser u = realmAdminUser();
        return E2eAdminSession.login(newBrowser(), realm, u.username(), PASSWORD);
    }

    private E2eAdminSession scoped(final String permission) {
        final String roleName = E2eSeed.unique("s-" + permission);
        String id = admin.post(base() + "/roles", Map.of("name", roleName)).json().path("roleId").asText();
        if (id.isBlank()) {
            id = roleId(roleName);
        }
        admin.put(base() + "/admin-roles/" + id, Map.of("permissions", List.of(permission)));
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("s-u"), PASSWORD);
        admin.post(base() + "/users/" + user.userId() + "/roles", Map.of("roleId", id));
        return E2eAdminSession.login(newBrowser(), realm, user.username(), PASSWORD);
    }
}
