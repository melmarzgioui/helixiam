/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import tools.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.helixiam.authorization.domain.audit.AuditQuery;
import io.helixiam.authorization.federation.wallet.WalletIdentityProvider;
import io.helixiam.authorization.federation.wallet.testwallet.Oid4vpWalletClient;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet;
import io.helixiam.authorization.federation.wallet.trust.tl.TrustedListFixtures;
import io.helixiam.authorization.service.audit.AuditLogService;
import io.helixiam.e2e.browser.HarnessEgressGuard;
import io.helixiam.testsupport.HarnessTls;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * EuTrustedListSource end to end, over real HTTP: an admin adds a trusted list source (a signed ETSI TS 119 612 list
 * served over https by a harness server), refreshes it from the console API, and points a wallet provider at it
 * instead of pasted anchors. A PID from the issuer on the list signs in; a PID from an issuer that is not on the list
 * is refused, and so is the listed issuer once the list withdraws it.
 */
class TrustedListWalletE2eTest extends AbstractE2eTest {

    private final AtomicReference<byte[]> served = new AtomicReference<>();
    private final TestPki.Leaf listSigner = TrustedListFixtures.signer("E2E TL Signer");
    private HttpsServer server;
    private WalletE2eFixture wallet;
    private E2eAdminSession admin;
    private String realm;
    private String alias;

    @BeforeEach
    void setUp() throws Exception {
        server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(HarnessTls.TLS.serverContext()));
        server.createContext("/tl.xml", ex -> {
            final byte[] body = served.get();
            ex.getResponseHeaders().add("Content-Type", "application/vnd.etsi.tsl+xml");
            ex.sendResponseHeaders(200, body.length);
            ex.getResponseBody().write(body);
            ex.close();
        });
        server.start();
        HarnessEgressGuard.allow(server.getAddress().getPort());

        wallet = new WalletE2eFixture(context);
        realm = E2eSeed.unique("tlwallet");
        seed().realm(realm);
        seed().confidentialClient(realm, "web", List.of("openid", "profile"));
        admin = adminSession();
        alias = E2eSeed.unique("eudi");
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    private String listUrl() {
        return "https://localhost:" + server.getAddress().getPort() + "/tl.xml";
    }

    private String lists() {
        return "/admin/realms/" + realm + "/trusted-lists";
    }

    private void serve(final long sequence, final TrustedListFixtures.Service... services) {
        final TrustedListFixtures.Spec spec = TrustedListFixtures.Spec.memberState("UT").sequence(sequence);
        for (final TrustedListFixtures.Service s : services) {
            spec.service(s);
        }
        served.set(TrustedListFixtures.signedXml(spec, listSigner));
    }

    private JsonNode createSource(final String name) {
        final E2eHttp.Response created = admin.post(lists(), Map.of("name", name, "url", listUrl(),
                "format", "ETSI_119612_XML", "signerCertificates", TestPki.pem(listSigner.certificate()),
                "serviceTypes", List.of(TrustedListFixtures.PID_TYPE), "graceHours", 24));
        assertThat(created.status()).as(created.toString()).isEqualTo(201);
        return created.json();
    }

    private JsonNode refresh(final String id) {
        final E2eHttp.Response refreshed = admin.post(lists() + "/" + id + "/refresh", Map.of());
        assertThat(refreshed.status()).as(refreshed.toString()).isEqualTo(200);
        return refreshed.json();
    }

    @Test
    void providerOnATrustedList_acceptsTheListedIssuer_andRefusesOthers() {
        serve(5, TrustedListFixtures.Service.granted("Listed PID Provider", wallet.wallet().pki().root()));
        final JsonNode source = createSource("ut-pid");
        assertThat(source.path("status").asText()).isEqualTo("NEVER");

        final JsonNode refreshed = refresh(source.path("id").asText());
        assertThat(refreshed.path("status").asText()).as(refreshed.toString()).isEqualTo("OK");
        assertThat(refreshed.path("anchorCount").asInt()).isEqualTo(1);
        assertThat(refreshed.path("sequenceNumber").asLong()).isEqualTo(5);
        assertThat(refreshed.path("nextUpdate").asText()).isNotBlank();
        final JsonNode anchors = admin.get(lists() + "/" + source.path("id").asText() + "/anchors").json();
        assertThat(anchors).hasSize(1);
        assertThat(anchors.get(0).path("provider").asText()).isEqualTo("Listed PID Provider");
        assertThat(anchors.get(0).path("country").asText()).isEqualTo("UT");
        assertThat(anchors.get(0).path("usable").asBoolean()).isTrue();
        assertAudited("TRUSTED_LIST_REFRESHED");

        // the provider has NO pasted anchors: its trust comes from the list only
        final WalletIdentityProvider provider = wallet.storedProvider(realm, alias,
                Map.of("trustAnchors", "", "trustedLists.sources", "[\"ut-pid\"]"));
        wallet.install(realm, provider);

        final Login listed = startLogin();
        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(listed.page()));
        final E2eHttp.Response accepted = wallet.respond(phone, request,
                WalletE2eFixture.pidWithNumber("PAN-" + UUID.randomUUID()));
        assertThat(accepted.status()).as(accepted.toString()).isEqualTo(200);
        assertThat(poll(listed).path("status").asText()).isEqualTo("COMPLETED");

        // an issuer that is not on the list
        assertThat(presentFrom(TestWallet.create())).isEqualTo("not_accepted");

        // the list withdraws the listed issuer: after the next refresh it is refused too
        serve(6, TrustedListFixtures.Service.granted("Listed PID Provider", wallet.wallet().pki().root())
                .withStatus(TrustedListFixtures.WITHDRAWN));
        assertThat(refresh(source.path("id").asText()).path("anchorCount").asInt()).isZero();
        assertThat(presentFrom(wallet.wallet())).isEqualTo("not_accepted");
    }

    @Test
    void listThatDoesNotVerify_isRefusedAndAudited_andGivesNoAnchors() {
        serve(5, TrustedListFixtures.Service.granted("Listed PID Provider", wallet.wallet().pki().root()));
        served.set(new String(served.get(), java.nio.charset.StandardCharsets.UTF_8)
                .replace("Listed PID Provider", "Forged PID Provider").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        final JsonNode source = createSource("forged");

        final JsonNode refreshed = refresh(source.path("id").asText());

        assertThat(refreshed.path("status").asText()).isEqualTo("ERROR");
        assertThat(refreshed.path("lastError").asText()).startsWith("SIGNATURE:");
        assertThat(refreshed.path("anchorCount").asInt()).isZero();
        assertAudited("TRUSTED_LIST_REFRESH_FAILED");
    }

    @Test
    void settings_areValidated_andNeedManageIdentityProviders() {
        final E2eHttp.Response bad = admin.post(lists(), Map.of("name", "bad name", "url", "http://tl.example/x.xml",
                "format", "ETSI_119612_XML", "signerCertificates", "nope", "serviceTypes", List.of()));
        assertThat(bad.status()).as(bad.toString()).isEqualTo(400);
        assertThat(bad.json().path("fieldErrors").has("name")).isTrue();
        assertThat(bad.json().path("fieldErrors").has("url")).isTrue();
        assertThat(bad.json().path("fieldErrors").has("signerCertificates")).isTrue();
        assertThat(bad.json().path("fieldErrors").has("serviceTypes")).isTrue();

        // a wallet provider naming a source the realm does not have is refused at write time
        final E2eHttp.Response provider = admin.post("/admin/realms/" + realm + "/identity-providers", Map.of(
                "alias", alias, "protocol", "eudi-wallet", "displayName", "Wallet", "enabled", true,
                "config", Map.of("accessKeyRef", wallet.importAccessKey(realm),
                        "trustedLists.sources", "[\"missing\"]")));
        assertThat(provider.status()).as(provider.toString()).isEqualTo(400);
        assertThat(provider.json().path("fieldErrors").path("config.trustedLists.sources").asText())
                .contains("missing");

        // no CSRF header: refused
        assertThat(admin.http().sendJson("POST", lists(), Map.of("name", "x")).status()).isEqualTo(403);
    }

    @Test
    void renamingASourceThatProvidersUse_isRefused_andUpdatesAreAuditedWithUrlAndSignerFingerprints() throws Exception {
        serve(5, TrustedListFixtures.Service.granted("Listed PID Provider", wallet.wallet().pki().root()));
        final JsonNode source = createSource("in-use");
        final String id = source.path("id").asText();
        final E2eHttp.Response provider = admin.post("/admin/realms/" + realm + "/identity-providers", Map.of(
                "alias", alias, "protocol", "eudi-wallet", "displayName", "Wallet", "enabled", true,
                "config", Map.of("accessKeyRef", wallet.importAccessKey(realm),
                        "trustedLists.sources", "[\"in-use\"]")));
        assertThat(provider.status()).as(provider.toString()).isEqualTo(201);

        final Map<String, Object> renamed = new java.util.LinkedHashMap<>(Map.of("name", "renamed", "url", listUrl(),
                "format", "ETSI_119612_XML", "signerCertificates", TestPki.pem(listSigner.certificate()),
                "serviceTypes", List.of(TrustedListFixtures.PID_TYPE), "graceHours", 24,
                "configVersion", source.path("configVersion").asLong()));
        final E2eHttp.Response refused = admin.put(lists() + "/" + id, renamed);
        assertThat(refused.status()).as(refused.toString()).isEqualTo(400);
        assertThat(refused.json().path("fieldErrors").path("name").asText()).contains(alias);

        // the same settings under the old name save, and the update is audited with the URL and signer fingerprint
        renamed.put("name", "in-use");
        renamed.put("graceHours", 48);
        assertThat(admin.put(lists() + "/" + id, renamed).status()).isEqualTo(200);
        final String fingerprint = java.util.HexFormat.of().formatHex(java.security.MessageDigest
                .getInstance("SHA-256").digest(listSigner.certificate().getEncoded()));
        final AuditLogService audit = context.getBean(AuditLogService.class);
        final Instant deadline = Instant.now().plusSeconds(5);
        String detail = "";
        while (Instant.now().isBefore(deadline) && !detail.contains(fingerprint)) {
            detail = audit.search(new AuditQuery(realm, "TRUSTED_LIST_UPDATE", null, null, null, 0, 10)).items()
                    .stream().map(r -> String.valueOf(r.detail())).reduce("", String::concat);
            Thread.sleep(25);
        }
        assertThat(detail).contains(fingerprint).contains(listUrl());

        // and while the provider uses it, the source cannot be deleted either
        final E2eHttp.Response deleted = admin.delete(lists() + "/" + id);
        assertThat(deleted.status()).as(deleted.toString()).isEqualTo(409);
        assertThat(deleted.json().path("message").asText()).contains(alias);
        assertThat(admin.get(lists() + "/" + id).status()).isEqualTo(200);
    }

    @Test
    void anEditOverAStaleRead_is409_andAnEditWithoutConfigVersion_is400() {
        serve(5, TrustedListFixtures.Service.granted("Listed PID Provider", wallet.wallet().pki().root()));
        final JsonNode source = createSource("two-admins");
        final String id = source.path("id").asText();
        final Map<String, Object> edit = new java.util.LinkedHashMap<>(Map.of("name", "two-admins", "url", listUrl(),
                "format", "ETSI_119612_XML", "signerCertificates", TestPki.pem(listSigner.certificate()),
                "serviceTypes", List.of(TrustedListFixtures.PID_TYPE), "graceHours", 48,
                "configVersion", source.path("configVersion").asLong()));

        final E2eHttp.Response first = admin.put(lists() + "/" + id, edit);
        assertThat(first.status()).as(first.toString()).isEqualTo(200);
        assertThat(first.json().path("configVersion").asLong()).isGreaterThan(source.path("configVersion").asLong());

        edit.put("graceHours", 12);
        final E2eHttp.Response stale = admin.put(lists() + "/" + id, edit);
        assertThat(stale.status()).as(stale.toString()).isEqualTo(409);
        assertThat(admin.get(lists() + "/" + id).json().path("graceHours").asInt()).isEqualTo(48);

        edit.remove("configVersion");
        final E2eHttp.Response missing = admin.put(lists() + "/" + id, edit);
        assertThat(missing.status()).isEqualTo(400);
        assertThat(missing.json().path("fieldErrors").has("configVersion")).isTrue();
    }

    @Test
    void anAdminWithoutManageIdentityProviders_getsForbidden() {
        final E2eAdminSession realmOnly = scopedAdmin("manage-realm");
        serve(5, TrustedListFixtures.Service.granted("Listed PID Provider", wallet.wallet().pki().root()));
        final String id = createSource("guarded").path("id").asText();

        assertThat(realmOnly.get(lists()).status()).isEqualTo(403);
        assertThat(realmOnly.get(lists() + "/" + id).status()).isEqualTo(403);
        assertThat(realmOnly.get(lists() + "/" + id + "/anchors").status()).isEqualTo(403);
        assertThat(realmOnly.post(lists(), Map.of("name", "x")).status()).isEqualTo(403);
        assertThat(realmOnly.post(lists() + "/" + id + "/refresh", Map.of()).status()).isEqualTo(403);
        assertThat(realmOnly.delete(lists() + "/" + id).status()).isEqualTo(403);
        assertThat(admin.get(lists() + "/" + id).status()).isEqualTo(200);
    }

    @Test
    void aViewOnlyAdmin_canReadButNotWrite() {
        // pentest-b INFO: a view-only admin must be able to read trusted lists (view-identity-providers) but not
        // write them (manage-identity-providers stays required for writes).
        serve(5, TrustedListFixtures.Service.granted("Listed PID Provider", wallet.wallet().pki().root()));
        final String id = createSource("view-only").path("id").asText();
        final E2eAdminSession viewOnly = scopedAdmin("view-identity-providers");

        assertThat(viewOnly.get(lists()).status()).isEqualTo(200);
        assertThat(viewOnly.get(lists() + "/" + id).status()).isEqualTo(200);
        assertThat(viewOnly.get(lists() + "/" + id + "/anchors").status()).isEqualTo(200);

        assertThat(viewOnly.post(lists(), Map.of("name", "x")).status()).isEqualTo(403);
        assertThat(viewOnly.post(lists() + "/" + id + "/refresh", Map.of()).status()).isEqualTo(403);
        assertThat(viewOnly.delete(lists() + "/" + id).status()).isEqualTo(403);
    }

    // ------------------------------------------------------------------------------------------------ helpers

    /** A user of {@link #realm} whose only admin permission is {@code permission}, logged in. */
    private E2eAdminSession scopedAdmin(final String permission) {
        final String roleName = E2eSeed.unique("tl-" + permission);
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
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("tl-scoped"), "Sc0ped-Admin-Passw0rd!");
        assertThat(admin.post("/admin/realms/" + realm + "/users/" + user.userId() + "/roles", Map.of("roleId", roleId))
                .status()).isEqualTo(204);
        return E2eAdminSession.login(newBrowser(), realm, user.username(), user.password());
    }

    /** Presents a PID from {@code issuer} in a fresh login; returns the plain-language failure reason (or status). */
    private String presentFrom(final TestWallet issuer) {
        final Login login = startLogin();
        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(login.page()));
        final Map<String, Object> claims = WalletE2eFixture.pidWithNumber("PAN-" + UUID.randomUUID());
        final TestWallet.SdJwtCredential cred = issuer.sdJwtPid(claims, Instant.now().minusSeconds(60),
                Instant.now().plusSeconds(3600), Optional.empty());
        final String presentation = issuer.present(cred, claims.keySet(), request.clientId(), request.nonce());
        final E2eHttp.Response posted = wallet.respondWith(phone, request, Map.of("pid_sd_jwt", List.of(presentation)));
        assertThat(posted.status()).as(posted.toString()).isEqualTo(400);
        final JsonNode status = poll(login);
        assertThat(status.path("status").asText()).isEqualTo("FAILED");
        return status.path("reason").asText();
    }

    private record Login(E2eHttp browser, String pageLocation, String page) {
    }

    private Login startLogin() {
        final E2eHttp browser = newBrowser();
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final String authorize = "/realms/" + realm + "/oauth2/authorize?response_type=code&client_id=web"
                + "&redirect_uri=" + E2eSeed.REDIRECT_URI + "&scope=openid%20profile&state=st&code_challenge="
                + pkce.challenge() + "&code_challenge_method=S256";
        browser.followRedirects(browser.get(authorize, "Accept", "text/html"));
        final E2eHttp.Response start = browser.get("/realms/" + realm + "/broker/" + alias);
        assertThat(start.status()).as(start.toString()).isEqualTo(302);
        final URI location = start.location();
        final String pageLocation = location.getPath() + "?" + location.getRawQuery();
        final E2eHttp.Response page = browser.get(pageLocation);
        assertThat(page.status()).as(page.toString()).isEqualTo(200);
        return new Login(browser, pageLocation, page.body());
    }

    private JsonNode poll(final Login login) {
        final String tx = WalletE2eFixture.txId(login.pageLocation());
        final String path = login.pageLocation().substring(0, login.pageLocation().indexOf("?")) + "/status?tx=" + tx;
        final E2eHttp.Response status = login.browser().get(path, "Accept", "application/json");
        assertThat(status.status()).as(status.toString()).isEqualTo(200);
        return status.json();
    }

    private void assertAudited(final String type) {
        final AuditLogService audit = context.getBean(AuditLogService.class);
        final Instant deadline = Instant.now().plusSeconds(5);
        while (Instant.now().isBefore(deadline)) {
            if (!audit.search(new AuditQuery(realm, type, null, null, null, 0, 10)).items().isEmpty()) {
                return;
            }
            try {
                Thread.sleep(25);
            } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        throw new AssertionError("no " + type + " audit record in realm " + realm);
    }
}
