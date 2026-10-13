/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import io.helixiam.authorization.federation.IdentityProviderRegistry;
import io.helixiam.authorization.federation.wallet.testwallet.Oid4vpWalletClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.DefaultApplicationArguments;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Final review F1: wallet connections created through the admin API (the console path) in more than one realm. Store
 * backed providers are keyed by (realm, alias): two realms may both keep the console's default alias
 * {@code eudi-wallet}; the startup load covers every realm; a write in one realm leaves every other realm's providers
 * loaded; a realm's login page lists only the providers that serve it.
 */
class WalletMultiRealmStoreE2eTest extends AbstractE2eTest {

    private static final String DEFAULT_ALIAS = "eudi-wallet"; // what the console wizard proposes in every realm

    private WalletE2eFixture wallet;
    private E2eAdminSession admin;
    private String realmA;
    private String realmB;
    private E2eSeed.SeededClient webA;
    private E2eSeed.SeededClient webB;

    @BeforeEach
    void setUp() {
        wallet = new WalletE2eFixture(context);
        admin = adminSession();
        realmA = E2eSeed.unique("wmr-a");
        realmB = E2eSeed.unique("wmr-b");
        seed().realm(realmA);
        seed().realm(realmB);
        webA = seed().confidentialClient(realmA, "web", List.of("openid", "profile"));
        webB = seed().confidentialClient(realmB, "web", List.of("openid", "profile"));
    }

    @Test
    void twoRealmsWithTheDefaultAlias_bothSignIn_alsoAfterARestart() {
        createWallet(realmA, DEFAULT_ALIAS);
        createWallet(realmB, DEFAULT_ALIAS);

        assertSignsIn(realmA, webA, DEFAULT_ALIAS);
        assertSignsIn(realmB, webB, DEFAULT_ALIAS);

        restart();

        assertSignsIn(realmA, webA, DEFAULT_ALIAS);
        assertSignsIn(realmB, webB, DEFAULT_ALIAS);
    }

    @Test
    void aWriteInRealmB_leavesRealmAsProvidersLoaded() {
        createWallet(realmA, DEFAULT_ALIAS);

        createWallet(realmB, E2eSeed.unique("eudi-b"));
        assertThat(admin.delete("/admin/realms/" + realmB + "/identity-providers/" + DEFAULT_ALIAS).status())
                .as("realm B has no provider of that alias").isEqualTo(404);

        assertThat(loginPage(realmA)).contains("/broker/" + DEFAULT_ALIAS);
        assertSignsIn(realmA, webA, DEFAULT_ALIAS);
    }

    @Test
    void theLoginPageOfRealmA_doesNotShowRealmBsWallet() {
        final String aliasA = E2eSeed.unique("eudi-a");
        final String aliasB = E2eSeed.unique("eudi-b");
        createWallet(realmA, aliasA);
        createWallet(realmB, aliasB);

        assertThat(loginPage(realmA)).contains("/broker/" + aliasA).doesNotContain("/broker/" + aliasB);
        assertThat(loginPage(realmB)).contains("/broker/" + aliasB).doesNotContain("/broker/" + aliasA);
        // ...and realm B's provider cannot be started under realm A at all.
        assertThat(newBrowser().get("/realms/" + realmA + "/broker/" + aliasB).location().getPath())
                .isNotEqualTo("/realms/" + realmA + "/broker/" + aliasB + "/wallet");
    }

    // ------------------------------------------------------------------------------------------------ helpers

    /** Creates a wallet connection in {@code realm} through the admin API, as the console does. */
    private void createWallet(final String realm, final String alias) {
        final Map<String, Object> body = new LinkedHashMap<>();
        body.put("alias", alias);
        body.put("protocol", "eudi-wallet");
        body.put("displayName", "EU Digital Identity Wallet");
        body.put("enabled", true);
        body.put("config", wallet.storedConfig(wallet.importAccessKey(realm)));
        final E2eHttp.Response created = admin.post("/admin/realms/" + realm + "/identity-providers", body);
        assertThat(created.status()).as(created.toString()).isEqualTo(201);
    }

    /** What a process restart does to the live registry: empty store-backed sets, then the startup load. */
    private void restart() {
        context.getBean(IdentityProviderRegistry.class).replaceAll(Map.of());
        assertThat(loginPage(realmA)).doesNotContain("/broker/" + DEFAULT_ALIAS);
        try {
            context.getBean("federationStoreStartupRefresh", ApplicationRunner.class)
                    .run(new DefaultApplicationArguments());
        } catch (final Exception e) {
            throw new AssertionError(e);
        }
    }

    private String loginPage(final String realm) {
        final E2eHttp.Response page = newBrowser().get("/realms/" + realm + "/login", "Accept", "text/html");
        assertThat(page.status()).as(page.toString()).isEqualTo(200);
        return page.body();
    }

    /** A cross-device wallet login at {@code realm}'s {@code web} client ends signed in with eIDAS high. */
    private void assertSignsIn(final String realm, final E2eSeed.SeededClient web, final String alias) {
        final E2eHttp browser = newBrowser();
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final String authorize = "/realms/" + realm + "/oauth2/authorize?response_type=code&client_id=web"
                + "&redirect_uri=" + E2eSeed.REDIRECT_URI + "&scope=openid%20profile&state=st&code_challenge="
                + pkce.challenge() + "&code_challenge_method=S256";
        final E2eHttp.Response loginPage = browser.followRedirects(browser.get(authorize, "Accept", "text/html"));
        assertThat(loginPage.body()).contains("/broker/" + alias);
        final E2eHttp.Response start = browser.get("/realms/" + realm + "/broker/" + alias);
        assertThat(start.status()).as(start.toString()).isEqualTo(302);
        final URI location = start.location();
        assertThat(location.getPath()).isEqualTo("/realms/" + realm + "/broker/" + alias + "/wallet");
        final String pageLocation = location.getPath() + "?" + location.getRawQuery();
        final E2eHttp.Response page = browser.get(pageLocation);
        assertThat(page.status()).as(page.toString()).isEqualTo(200);

        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(page.body()));
        final E2eHttp.Response posted = wallet.respond(phone, request,
                WalletE2eFixture.pidWithNumber("PAN-" + UUID.randomUUID()));
        assertThat(posted.status()).as(posted.toString()).isEqualTo(200);

        final String statusPath = pageLocation.substring(0, pageLocation.indexOf('?')) + "/status?tx="
                + WalletE2eFixture.txId(pageLocation);
        final String next = browser.get(statusPath, "Accept", "application/json").json().path("next").asText();
        final E2eHttp.Response signedIn = browser.followRedirectsUntil(browser.get(next),
                r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        assertThat(signedIn.locationStartsWith(E2eSeed.REDIRECT_URI)).as(signedIn + "\n" + browser.trail(10)).isTrue();
        final OidcFlow oidc = new OidcFlow(browser, realm);
        final OidcFlow.Tokens tokens = oidc.exchangeCode("web", web.secret(), E2eSeed.REDIRECT_URI,
                OidcFlow.query(signedIn.location()).get("code"), pkce.verifier());
        try {
            assertThat(oidc.verify(tokens.idToken()).getStringClaim("acr")).isEqualTo("http://eidas.europa.eu/LoA/high");
        } catch (final java.text.ParseException e) {
            throw new AssertionError(e);
        }
    }
}
