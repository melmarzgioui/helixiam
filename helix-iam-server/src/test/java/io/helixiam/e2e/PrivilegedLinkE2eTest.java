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
import io.helixiam.authorization.service.adminrbac.PrivilegedLegacyLinkReport;
import io.helixiam.authorization.service.federation.FederatedLinkService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Round 6 rulings: links made before the upgrade keep signing their administrators in (LEGACY, reported at start-up);
 * new links to an administrator need the account console's link flow (SELF) or a realm admin's confirmation; a link
 * made by matching an e-mail address never signs in an administrator, and every refusal is audited.
 */
class PrivilegedLinkE2eTest extends AbstractE2eTest {

    static {
        System.setProperty("helix.egress.allow-private", "true");
        System.setProperty("helix.egress.allowed-private-hosts", "127.0.0.1");
    }

    private static final String PASSWORD = "Privileged-Link-Passw0rd!";

    private String realm;
    private E2eAdminSession admin;
    private String adminRoleId;
    private HttpServer server;
    private String issuer;
    private final AtomicReference<String> nonce = new AtomicReference<>();
    private final AtomicReference<String> subject = new AtomicReference<>("ext-sub");
    private final AtomicReference<String> email = new AtomicReference<>();
    private FederatedLinkService links;

    @BeforeEach
    void setUp() throws Exception {
        realm = E2eSeed.unique("plink");
        seed().realm(realm);
        admin = adminSession();
        adminRoleId = roleId("admin");
        links = context.getBean(FederatedLinkService.class);
        final RSAKey key = new RSAKeyGenerator(2048).keyID("k1").generate();
        final String jwks = new JWKSet(key.toPublicJWK()).toString();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        issuer = "http://127.0.0.1:" + server.getAddress().getPort();
        server.createContext("/jwks", ex -> respond(ex, jwks));
        server.createContext("/token", ex -> {
            try {
                final JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().issuer(issuer).subject(subject.get())
                        .audience("helix").claim("nonce", nonce.get()).issueTime(new Date())
                        .expirationTime(new Date(System.currentTimeMillis() + 300_000));
                if (email.get() != null) {
                    claims.claim("email", email.get()).claim("email_verified", true);
                }
                final SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("k1").build(),
                        claims.build());
                jwt.sign(new RSASSASigner(key));
                respond(ex, "{\"id_token\":\"" + jwt.serialize() + "\",\"access_token\":\"a\",\"token_type\":\"Bearer\"}");
            } catch (final Exception e) {
                respond(ex, "{}");
            }
        });
        server.start();
        permissiveTokenClient();
        final Map<String, Object> idp = new LinkedHashMap<>();
        idp.put("alias", "corp");
        idp.put("protocol", "oidc");
        idp.put("displayName", "Corp sign-in");
        idp.put("enabled", true);
        idp.put("config", Map.of("clientId", "helix", "clientSecret", "corp-secret-0123456789", "issuer", issuer,
                "authorizationEndpoint", issuer + "/authorize", "tokenEndpoint", issuer + "/token",
                "jwksUri", issuer + "/jwks"));
        assertThat(admin.post(base() + "/identity-providers", idp).status()).isEqualTo(201);
        Thread.sleep(1500);
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    // ------------------------------------------------------------------------------------- grandfathered links

    @Test
    void anAdministratorLinkedBeforeTheUpgradeStillSignsIn_andIsReported() {
        final E2eSeed.SeededUser boss = realmAdminUser();
        // What V86 makes of an rc.11 link (the backfill itself: FlywayRealmKeyCertificatesTest).
        links.link("corp", "ext-sub", boss.userId(), LinkProvenance.LEGACY);

        assertThat(adminRolesStatus(brokerLogin())).isEqualTo(200);
        assertThat(context.getBean(PrivilegedLegacyLinkReport.class).check())
                .anyMatch(f -> realm.equals(f.realm()) && boss.username().equals(f.username())
                        && "corp".equals(f.idpAlias()));
    }

    // ------------------------------------------------------------------------------------- new links

    @Test
    void aNewEmailLinkToAnAdministratorIsRefused_andAudited() throws Exception {
        final E2eSeed.SeededUser boss = realmAdminUser();
        email.set(boss.dto().email());
        subject.set("attacker-sub");

        assertThat(adminRolesStatus(brokerLogin())).isNotEqualTo(200);
        assertThat(links.findLinkedUser("corp", "attacker-sub")).isEmpty();
        assertThat(audited("PRIVILEGED_LINK_REFUSED")).isTrue();
    }

    @Test
    void theAccountConsoleLinkNeedsAFreshSignIn_writesSelf_andThenSignsIn() {
        final E2eSeed.SeededUser boss = realmAdminUser();
        final E2eHttp browser = E2eAdminSession.login(newBrowser(), realm, boss.username(), PASSWORD).http();
        browser.get("/realms/" + realm + "/e2e/age-auth-time?seconds=600");
        final String account = "/realms/" + realm + "/account";
        final E2eHttp.Response page = browser.get(account);
        assertThat(page.body()).contains("identities-heading").contains("Corp sign-in");

        // Step-up first: the link continues after the user signs in again.
        final E2eHttp.Response asked = browser.postForm(account + "/identities/link",
                Map.of("_csrf", E2eHttp.csrf(page.body()), "alias", "corp"));
        assertThat(asked.header("Location").orElse("")).contains("/account/reauth").contains("next=identity-link");
        final E2eHttp.Response reauth = browser.get(asked.location().toString());
        final Map<String, String> form = new LinkedHashMap<>(E2eHttp.hiddenInputs(reauth.body()));
        form.put("password", PASSWORD);
        final E2eHttp.Response atProvider = browser.followRedirectsUntil(
                browser.postForm(account + "/reauth", form), r -> r.header("Location").orElse("").startsWith(issuer));
        final Map<String, String> q = OidcFlow.query(java.net.URI.create(atProvider.header("Location").orElse("")));
        nonce.set(q.get("nonce"));
        final E2eHttp.Response back = browser.get("/realms/" + realm + "/broker/corp/callback?code=x&state="
                + enc(q.get("state")));
        assertThat(back.header("Location").orElse("")).contains("/account");

        assertThat(links.findLinkedUser("corp", "ext-sub")).contains(boss.userId());
        assertThat(links.provenance("corp", "ext-sub")).contains(LinkProvenance.SELF);
        assertThat(adminRolesStatus(brokerLogin())).isEqualTo(200);
    }

    @Test
    void theAccountConsoleLinkRefusesAnIdentityOfSomeoneElse() {
        final E2eSeed.SeededUser other = seed().user(realm, E2eSeed.unique("other"), PASSWORD);
        links.link("corp", "ext-sub", other.userId(), LinkProvenance.JIT);
        final E2eSeed.SeededUser boss = realmAdminUser();
        final E2eHttp browser = E2eAdminSession.login(newBrowser(), realm, boss.username(), PASSWORD).http();
        final String account = "/realms/" + realm + "/account";
        final E2eHttp.Response atProvider = browser.followRedirectsUntil(browser.postForm(account + "/identities/link",
                Map.of("_csrf", E2eHttp.csrf(browser.get(account).body()), "alias", "corp")),
                r -> r.header("Location").orElse("").startsWith(issuer));
        final Map<String, String> q = OidcFlow.query(java.net.URI.create(atProvider.header("Location").orElse("")));
        nonce.set(q.get("nonce"));
        browser.get("/realms/" + realm + "/broker/corp/callback?code=x&state=" + enc(q.get("state")));

        assertThat(links.findLinkedUser("corp", "ext-sub")).contains(other.userId());
    }

    @Test
    void aLinkStartedWithoutTheSessionsIntentIsRefused() {
        final E2eSeed.SeededUser boss = realmAdminUser();
        final E2eHttp browser = E2eAdminSession.login(newBrowser(), realm, boss.username(), PASSWORD).http();
        final E2eHttp.Response forged = browser.get("/realms/" + realm + "/broker/corp?link=forged-token");
        assertThat(forged.header("Location").orElse("")).contains("/account").doesNotStartWith(issuer);
    }

    // ------------------------------------------------------------------------------------- confirm and revoke

    @Test
    void aRealmAdminConfirmsALink_andRevokingTrustBlocksTheSignIn() {
        final E2eSeed.SeededUser boss = realmAdminUser();
        links.link("corp", "ext-sub", boss.userId(), LinkProvenance.AUTO);
        assertThat(adminRolesStatus(brokerLogin())).isNotEqualTo(200);

        final String path = base() + "/users/" + boss.userId() + "/federated-identities";
        final E2eAdminSession mu = scoped("manage-users");
        assertThat(mu.get(path).json().path("canManageTrust").asBoolean()).isFalse();
        assertThat(mu.post(path + "/corp/confirm", Map.of()).status()).isEqualTo(403);

        final E2eAdminSession ra = realmAdmin();
        final JsonNode listed = ra.get(path).json();
        assertThat(listed.path("canManageTrust").asBoolean()).isTrue();
        assertThat(listed.path("identities").get(0).path("createdVia").asText()).isEqualTo("AUTO");
        assertThat(ra.post(path + "/corp/confirm", Map.of()).status()).isEqualTo(204);
        assertThat(links.provenance("corp", "ext-sub")).contains(LinkProvenance.ADMIN_CONFIRMED);
        assertThat(adminRolesStatus(brokerLogin())).isEqualTo(200);

        assertThat(mu.post(path + "/corp/revoke-trust", Map.of()).status()).isEqualTo(403);
        assertThat(ra.post(path + "/corp/revoke-trust", Map.of()).status()).isEqualTo(204);
        assertThat(adminRolesStatus(brokerLogin())).isNotEqualTo(200);
        assertThat(audited("FEDERATED_LINK_CONFIRMED")).isTrue();
        assertThat(audited("FEDERATED_LINK_TRUST_REVOKED")).isTrue();
    }

    // ------------------------------------------------------------------------------------- helix-cli

    @Test
    void aNarrowedCliClientSurvivesARestart_andAWidenedOneIsCorrected() {
        final var bootstrap = context.getBean(io.helixiam.authorization.service.client.CliClientBootstrapService.class);
        bootstrap.ensureCliClient(realm);
        final var clients = context.getBean(io.helixiam.authorization.repository.ServiceProviderRepository.class);
        final var cli = clients.findByClientIdAndRealmIdAndDeleted("helix-cli", realm, false).orElseThrow();
        cli.setAuthorizationGrantTypes("authorization_code,refresh_token");
        cli.setRedirectUris("http://127.0.0.1:53682/cli/done");
        clients.save(cli);
        bootstrap.ensureCliClient(realm);
        var now = clients.findByClientIdAndRealmIdAndDeleted("helix-cli", realm, false).orElseThrow();
        assertThat(now.getRedirectUris()).containsExactly("http://127.0.0.1:53682/cli/done");
        assertThat(now.getAuthorizationGrantTypes()).hasSize(2);

        now.setRedirectUris("http://127.0.0.1:53682/cli/done,https://evil.example/cb");
        now.setAuthorizationGrantTypes("authorization_code,client_credentials");
        now.setPublicClient(false);
        clients.save(now);
        bootstrap.ensureCliClient(realm);
        now = clients.findByClientIdAndRealmIdAndDeleted("helix-cli", realm, false).orElseThrow();
        assertThat(now.getRedirectUris()).containsExactly("http://127.0.0.1:53682/cli/done");
        assertThat(now.getAuthorizationGrantTypes()).extracting(g -> g.getValue()).containsExactly("authorization_code");
        assertThat(now.getPublicClient()).isTrue();
    }

    // ------------------------------------------------------------------------------------- helpers

    private E2eHttp brokerLogin() {
        final E2eHttp browser = newBrowser();
        final E2eHttp.Response start = browser.get("/realms/" + realm + "/broker/corp");
        final Map<String, String> q = OidcFlow.query(java.net.URI.create(start.header("Location").orElse("")));
        nonce.set(q.get("nonce"));
        browser.followRedirects(browser.get("/realms/" + realm + "/broker/corp/callback?code=x&state="
                + enc(q.get("state"))));
        return browser;
    }

    private int adminRolesStatus(final E2eHttp browser) {
        return browser.get(base() + "/admin-roles", "Accept", "application/json").status();
    }

    /** Whether the realm's audit log holds an event of {@code type} (persisted asynchronously). */
    private boolean audited(final String type) {
        for (int i = 0; i < 40; i++) {
            final JsonNode page = admin.get(base() + "/events?type=" + type).json();
            if (page.path("total").asLong() > 0) {
                return true;
            }
            try {
                Thread.sleep(150);
            } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }

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
