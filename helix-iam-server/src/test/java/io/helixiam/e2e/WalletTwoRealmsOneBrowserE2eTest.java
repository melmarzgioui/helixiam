/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import io.helixiam.authorization.federation.wallet.testwallet.Oid4vpWalletClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Production readiness item 2: the broker keeps its per-login session attributes (state, browser binding, wallet
 * transaction) per (realm, alias). Two realms both using the console's default alias {@code eudi-wallet}, signed into
 * from one browser at the same time, no longer clobber each other: both logins complete. Before, starting realm B's
 * login discarded realm A's wallet transaction and replaced A's state and binding, so A's login failed.
 */
class WalletTwoRealmsOneBrowserE2eTest extends AbstractE2eTest {

    private static final String ALIAS = "eudi-wallet";

    private WalletE2eFixture wallet;
    private String realmA;
    private String realmB;

    @BeforeEach
    void setUp() {
        wallet = new WalletE2eFixture(context);
        realmA = E2eSeed.unique("w2r-a");
        realmB = E2eSeed.unique("w2r-b");
        seed().realm(realmA);
        seed().realm(realmB);
        seed().confidentialClient(realmA, "web", List.of("openid", "profile"));
        seed().confidentialClient(realmB, "web", List.of("openid", "profile"));
        createWallet(realmA);
        createWallet(realmB);
    }

    @Test
    void twoConcurrentWalletLogins_inTwoRealms_withTheSameAlias_inOneBrowser_bothComplete() {
        final E2eHttp browser = newBrowser();
        final Started a = start(browser, realmA);
        final Started b = start(browser, realmB); // the same browser, the same alias, before A finished

        assertCompletes(browser, a);
        assertCompletes(browser, b);
    }

    // ------------------------------------------------------------------------------------------------ helpers

    private record Started(String realm, String pageLocation, String walletPageHtml) {
    }

    /** Opens {@code realm}'s login page and starts its wallet login: the wallet page (cross-device QR). */
    private Started start(final E2eHttp browser, final String realm) {
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final String authorize = "/realms/" + realm + "/oauth2/authorize?response_type=code&client_id=web"
                + "&redirect_uri=" + E2eSeed.REDIRECT_URI + "&scope=openid%20profile&state=st&code_challenge="
                + pkce.challenge() + "&code_challenge_method=S256";
        final E2eHttp.Response loginPage = browser.followRedirects(browser.get(authorize, "Accept", "text/html"));
        assertThat(loginPage.body()).contains("/broker/" + ALIAS);
        final E2eHttp.Response begun = browser.get("/realms/" + realm + "/broker/" + ALIAS);
        assertThat(begun.status()).as(begun.toString()).isEqualTo(302);
        final URI location = begun.location();
        assertThat(location.getPath()).isEqualTo("/realms/" + realm + "/broker/" + ALIAS + "/wallet");
        final String pageLocation = location.getPath() + "?" + location.getRawQuery();
        final E2eHttp.Response page = browser.get(pageLocation);
        assertThat(page.status()).as(page.toString()).isEqualTo(200);
        return new Started(realm, pageLocation, page.body());
    }

    /**
     * The phone answers {@code started}'s request; the browser's status poll hands it the callback, and the callback
     * signs it in to that realm (never the federation error page).
     */
    private void assertCompletes(final E2eHttp browser, final Started started) {
        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(started.walletPageHtml()));
        final E2eHttp.Response posted = wallet.respond(phone, request,
                WalletE2eFixture.pidWithNumber("PAN-" + UUID.randomUUID()));
        assertThat(posted.status()).as(started.realm() + ": " + posted).isEqualTo(200);

        final String statusPath = started.pageLocation().substring(0, started.pageLocation().indexOf('?'))
                + "/status?tx=" + WalletE2eFixture.txId(started.pageLocation());
        final E2eHttp.Response status = browser.get(statusPath, "Accept", "application/json");
        assertThat(status.status()).as(started.realm() + ": " + status).isEqualTo(200);
        final String next = status.json().path("next").asText();
        assertThat(next).as(started.realm() + ": " + status.body()).isNotBlank();

        final E2eHttp.Response callback = browser.get(next);
        assertThat(callback.status()).as(started.realm() + ": " + callback).isEqualTo(302);
        assertThat(callback.location().toString()).as(started.realm() + " callback")
                .doesNotContain("error").doesNotContain("/login");

        // Signed in to that realm: a new authorization request there is answered with a code, no login page.
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final String authorize = "/realms/" + started.realm() + "/oauth2/authorize?response_type=code&client_id=web"
                + "&redirect_uri=" + E2eSeed.REDIRECT_URI + "&scope=openid%20profile&state=st2&code_challenge="
                + pkce.challenge() + "&code_challenge_method=S256";
        final E2eHttp.Response code = browser.followRedirectsUntil(browser.get(authorize, "Accept", "text/html"),
                r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        assertThat(code.locationStartsWith(E2eSeed.REDIRECT_URI)).as(started.realm() + "\n" + browser.trail(10))
                .isTrue();
    }

    private void createWallet(final String realm) {
        final Map<String, Object> body = new LinkedHashMap<>();
        body.put("alias", ALIAS);
        body.put("protocol", "eudi-wallet");
        body.put("displayName", "EU Digital Identity Wallet");
        body.put("enabled", true);
        body.put("config", wallet.storedConfig(wallet.importAccessKey(realm)));
        final E2eHttp.Response created = adminSession().post("/admin/realms/" + realm + "/identity-providers", body);
        assertThat(created.status()).as(created.toString()).isEqualTo(201);
    }
}
