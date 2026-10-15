/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import tools.jackson.databind.JsonNode;
import io.helixiam.authorization.federation.wallet.VerifiedPresentation;
import io.helixiam.authorization.federation.wallet.WalletIdentityProvider;
import io.helixiam.authorization.federation.wallet.WalletLinkService;
import io.helixiam.authorization.federation.wallet.WalletSubject;
import io.helixiam.authorization.federation.wallet.WalletSubjectResolver;
import io.helixiam.authorization.federation.wallet.dcql.MatchedPresentations;
import io.helixiam.authorization.federation.wallet.testwallet.Oid4vpWalletClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Task 21b: "Link EU Digital Identity Wallet" from the account console, over real HTTP. A signed-in user (password)
 * starts a LINK wallet transaction from the console (a recent sign-in required), the test wallet answers on the same
 * wallet page, and the browser's callback links the resolved subject to that user only. A LINK transaction never signs
 * anyone in; the link is the only way a wallet without an administrative number reaches an account.
 */
class WalletLinkE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Wallet-Link-Passw0rd-2026!";

    private WalletE2eFixture wallet;
    private String realm;
    private E2eSeed.SeededClient web;
    /** A provider that accepts the weak attribute-tuple subject (links a wallet without a number). */
    private String alias;
    private WalletIdentityProvider provider;
    private E2eSeed.SeededUser ada;

    @BeforeEach
    void setUp() {
        wallet = new WalletE2eFixture(context);
        realm = E2eSeed.unique("wlink");
        seed().realm(realm);
        web = seed().confidentialClient(realm, "web", List.of("openid", "profile"));
        alias = E2eSeed.unique("eudi-link");
        provider = wallet.storedProvider(realm, alias, Map.of("subject.acknowledgeWeakSubject", "true"));
        wallet.install(realm, provider);
        ada = seed().user(realm, E2eSeed.unique("ada"), PASSWORD);
    }

    // ------------------------------------------------------------------------------------------------ happy paths

    @Test
    void aWalletWithoutANumber_linkedFromTheConsole_thenSignsInToThatAccount() {
        final E2eHttp console = signIn(ada);
        assertThat(console.get(account()).body()).as("the console offers the wallet")
                .contains("data-alias=\"" + alias + "\"").contains("Link wallet");

        final String done = linkWith(console, alias, WalletE2eFixture.pidWithoutNumber());

        assertThat(done).contains("id=\"wallet-status\"").contains("Your wallet is linked.");
        assertThat(linkedRow(done, alias)).contains("Linked").doesNotContain(tupleOf(WalletE2eFixture.pidWithoutNumber()));
        // Later, a wallet-only sign-in (no password) lands on that account.
        assertThat(walletSignIn(alias, WalletE2eFixture.pidWithoutNumber())).isEqualTo(ada.userId());
    }

    @Test
    void aWalletWithANumber_isLinkedByItsNumber_andItsTuple_soEitherSignsIn() {
        final String number = "PAN-" + UUID.randomUUID();
        linkWith(signIn(ada), alias, WalletE2eFixture.pidWithNumber(number));

        final WalletLinkService links = context.getBean(WalletLinkService.class);
        assertThat(links.find(realm, alias, numberSubject(number))).contains(ada.userId());
        assertThat(links.find(realm, alias, new WalletSubject.Tuple(tupleOf(WalletE2eFixture.pidWithoutNumber()))))
                .contains(ada.userId());
        assertThat(walletSignIn(alias, WalletE2eFixture.pidWithNumber(number))).isEqualTo(ada.userId());
        assertThat(countWalletAccounts()).as("no account was created").isZero();
    }

    // ------------------------------------------------------------------------------------------------ refusals

    @Test
    void aSecondPersonWithADifferentTuple_cannotUseTheLink() {
        linkWith(signIn(ada), alias, WalletE2eFixture.pidWithoutNumber());
        final Map<String, Object> max = new LinkedHashMap<>(WalletE2eFixture.pidWithoutNumber());
        max.put("given_name", "Max");

        final E2eHttp.Response landed = walletSignInLanding(alias, max);

        assertThat(landed.body()).contains("id=\"walletLinkRequired\"");
        assertThat(landed.body()).doesNotContain(ada.username());
        assertThat(countWalletAccounts()).isZero();
    }

    @Test
    void aLinkCallbackFromAnotherUsersSession_isRefused_andNothingIsLinked() {
        final E2eHttp adaBrowser = signIn(ada);
        final String next = verifiedLink(adaBrowser, alias, WalletE2eFixture.pidWithoutNumber());
        final E2eSeed.SeededUser bob = seed().user(realm, E2eSeed.unique("bob"), PASSWORD);
        final E2eHttp bobBrowser = signIn(bob);

        final E2eHttp.Response stolen = bobBrowser.get(next);
        final String bobAccount = bobBrowser.followRedirects(stolen).body();

        assertThat(bobAccount).contains("id=\"wallet-error\"").contains("could not be linked");
        final WalletLinkService links = context.getBean(WalletLinkService.class);
        final WalletSubject.Tuple tuple = new WalletSubject.Tuple(tupleOf(WalletE2eFixture.pidWithoutNumber()));
        assertThat(links.find(realm, alias, tuple)).as("nothing linked to bob").isEmpty();
        // A callback with no session at all goes to sign-in and links nothing either.
        final E2eHttp.Response anonymous = newBrowser().get(next);
        assertThat(anonymous.location().getPath()).isEqualTo("/realms/" + realm + "/login");
        assertThat(links.find(realm, alias, tuple)).isEmpty();

        // ...and the code still works for the browser and user it belongs to.
        assertThat(adaBrowser.followRedirects(adaBrowser.get(next)).body()).contains("Your wallet is linked.");
        assertThat(links.find(realm, alias, tuple)).contains(ada.userId());
    }

    @Test
    void withoutANumber_andTheProviderNotAcceptingTheTuple_theLinkIsRefusedWithAnExplanation() {
        final String strict = E2eSeed.unique("eudi-strict");
        wallet.install(realm, provider, wallet.storedProvider(realm, strict, Map.of()));

        final String done = linkWith(signIn(ada), strict, WalletE2eFixture.pidWithoutNumber());

        assertThat(done).contains("id=\"wallet-error\"")
                .contains("only links wallets that carry a personal administrative number");
        assertThat(linkedRow(done, strict)).doesNotContain("hx-badge-ok");
        assertThat(context.getBean(WalletLinkService.class).find(realm, strict,
                new WalletSubject.Tuple(tupleOf(WalletE2eFixture.pidWithoutNumber())))).isEmpty();
    }

    @Test
    void aWalletLinkedToAnotherAccount_isRefused_withoutSayingWhichAccount() {
        final E2eSeed.SeededUser bob = seed().user(realm, E2eSeed.unique("bob"), PASSWORD);
        linkWith(signIn(bob), alias, WalletE2eFixture.pidWithoutNumber());

        final String done = linkWith(signIn(ada), alias, WalletE2eFixture.pidWithoutNumber());

        assertThat(done).contains("This wallet is already linked to another account");
        assertThat(done).doesNotContain(bob.username()).doesNotContain(bob.userId());
        assertThat(context.getBean(WalletLinkService.class).find(realm, alias,
                new WalletSubject.Tuple(tupleOf(WalletE2eFixture.pidWithoutNumber())))).contains(bob.userId());
    }

    @Test
    void unlink_needsARecentSignIn_andThenAWalletSignInIsSentToTheLinkPage() {
        final E2eHttp console = signIn(ada);
        linkWith(console, alias, WalletE2eFixture.pidWithoutNumber());

        console.get("/realms/" + realm + "/e2e/age-auth-time?seconds=600");
        final E2eHttp.Response stale = console.get(account() + "/wallet/unlink?alias=" + alias);
        assertThat(stale.location().toString()).endsWith("/account/reauth?next=wallets");

        console.get("/realms/" + realm + "/e2e/age-auth-time?seconds=-600"); // fresh again
        final E2eHttp.Response confirm = console.get(account() + "/wallet/unlink?alias=" + alias);
        assertThat(confirm.status()).as(confirm.toString()).isEqualTo(200);
        assertThat(confirm.body()).contains("id=\"wallet-unlink-form\"");
        final E2eHttp.Response unlinked = console.postForm(account() + "/wallet/unlink",
                Map.of("_csrf", E2eHttp.csrf(confirm.body()), "alias", alias));
        assertThat(console.followRedirects(unlinked).body()).contains("Your wallet is unlinked.");

        final E2eHttp.Response landed = walletSignInLanding(alias, WalletE2eFixture.pidWithoutNumber());
        assertThat(landed.body()).contains("id=\"walletLinkRequired\"");
    }

    @Test
    void linking_needsARecentSignIn() {
        final E2eHttp console = signIn(ada);
        final String csrf = E2eHttp.csrf(console.get(account()).body());
        console.get("/realms/" + realm + "/e2e/age-auth-time?seconds=600");

        final E2eHttp.Response stale = console.postForm(account() + "/wallet/link", Map.of("_csrf", csrf, "alias", alias));

        assertThat(stale.location().toString()).endsWith("/account/reauth?next=wallets");
    }

    @Test
    void linkAndUnlink_needTheCsrfToken_andASignIn() {
        final E2eHttp console = signIn(ada);
        assertThat(console.postForm(account() + "/wallet/link", Map.of("alias", alias)).status()).isEqualTo(403);
        assertThat(console.postForm(account() + "/wallet/unlink", Map.of("alias", alias)).status()).isEqualTo(403);

        final E2eHttp.Response anonymous = newBrowser().get(account() + "/wallet/unlink?alias=" + alias);
        assertThat(anonymous.location().getPath()).isEqualTo("/realms/" + realm + "/login");
    }

    @Test
    void aWalletProviderOfAnotherRealm_is404_forLinkCallbackAndUnlink() {
        final String otherRealm = E2eSeed.unique("wlink-b");
        seed().realm(otherRealm);
        final String foreign = E2eSeed.unique("eudi-foreign");
        wallet.install(realm, provider, wallet.storedProvider(otherRealm, foreign, Map.of()));
        final E2eHttp console = signIn(ada);
        final String csrf = E2eHttp.csrf(console.get(account()).body());

        assertThat(console.get(account()).body()).doesNotContain(foreign);
        assertThat(console.postForm(account() + "/wallet/link", Map.of("_csrf", csrf, "alias", foreign)).status())
                .isEqualTo(404);
        assertThat(console.postForm(account() + "/wallet/link", Map.of("_csrf", csrf, "alias", "no-such")).status())
                .isEqualTo(404);
        assertThat(console.get(account() + "/wallet/" + foreign + "/callback?response_code=x").status())
                .isEqualTo(404);
        assertThat(console.get(account() + "/wallet/unlink?alias=" + foreign).status()).isEqualTo(404);
        assertThat(console.postForm(account() + "/wallet/unlink", Map.of("_csrf", csrf, "alias", foreign)).status())
                .isEqualTo(404);
    }

    /** Ruling 2: a LINK transaction never signs anyone in, even when its code reaches the login callback. */
    @Test
    void aLinkTransactionsCode_atTheLoginCallback_signsNobodyIn() {
        final E2eHttp console = signIn(ada);
        final String next = verifiedLink(console, alias, WalletE2eFixture.pidWithoutNumber());
        final String code = next.substring(next.indexOf("response_code=") + 14);

        final E2eHttp other = newBrowser();
        other.followRedirects(other.get("/realms/" + realm + "/login"));
        final E2eHttp.Response login = other.get("/realms/" + realm + "/broker/" + alias + "/callback?response_code="
                + code);

        assertThat(login.location().toString()).endsWith("/login?error=federation");
        assertThat(other.get(account()).location().getPath()).as("still signed out")
                .isEqualTo("/realms/" + realm + "/login");
    }

    // ------------------------------------------------------------------------------------------------ helpers

    private String account() {
        return "/realms/" + realm + "/account";
    }

    private E2eHttp signIn(final E2eSeed.SeededUser user) {
        return E2eAdminSession.login(newBrowser(), realm, user.username(), PASSWORD).http();
    }

    /** Starts a link from the console, lets the test wallet answer from "another device", returns the callback. */
    private String verifiedLink(final E2eHttp console, final String providerAlias, final Map<String, Object> pid) {
        final String csrf = E2eHttp.csrf(console.get(account()).body());
        final E2eHttp.Response start = console.postForm(account() + "/wallet/link",
                Map.of("_csrf", csrf, "alias", providerAlias));
        assertThat(start.status()).as(start.toString()).isEqualTo(302);
        final URI location = start.location();
        assertThat(location.getPath()).isEqualTo("/realms/" + realm + "/broker/" + providerAlias + "/wallet");
        final String pageLocation = location.getPath() + "?" + location.getRawQuery();
        final E2eHttp.Response page = console.get(pageLocation);
        assertThat(page.status()).as(page.toString()).isEqualTo(200);
        assertThat(page.body()).contains("Link your EUDI Wallet");

        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(page.body()));
        assertThat(wallet.respond(phone, request, pid).status()).isEqualTo(200);

        final String status = pageLocation.substring(0, pageLocation.indexOf('?')) + "/status?"
                + location.getRawQuery();
        final JsonNode polled = console.get(status, "Accept", "application/json").json();
        assertThat(polled.path("status").asText()).isEqualTo("COMPLETED");
        final String next = polled.path("next").asText();
        assertThat(next).matches("/realms/" + realm + "/account/wallet/" + providerAlias
                + "/callback\\?response_code=[A-Za-z0-9_-]+");
        return next;
    }

    /** The whole link: start, wallet, callback; returns the console page the browser lands on. */
    private String linkWith(final E2eHttp console, final String providerAlias, final Map<String, Object> pid) {
        final String next = verifiedLink(console, providerAlias, pid);
        final E2eHttp.Response callback = console.get(next);
        assertThat(callback.status()).as(callback.toString()).isEqualTo(302);
        assertThat(callback.location().getPath()).isEqualTo(account());
        final E2eHttp.Response landed = console.followRedirects(callback);
        assertThat(landed.status()).isEqualTo(200);
        return landed.body();
    }

    /** The console's row of one wallet provider. */
    private static String linkedRow(final String html, final String providerAlias) {
        final int start = html.indexOf("data-alias=\"" + providerAlias + "\"");
        assertThat(start).as("a row for " + providerAlias).isNotNegative();
        final int end = html.indexOf("</li>", start);
        return html.substring(start, end);
    }

    /** A wallet-only sign-in at the client; returns the ID token subject. */
    private String walletSignIn(final String providerAlias, final Map<String, Object> pid) {
        final E2eHttp browser = newBrowser();
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final String next = walletLoginNext(browser, pkce, providerAlias, pid);
        final E2eHttp.Response signedIn = browser.followRedirectsUntil(browser.get(next),
                r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        assertThat(signedIn.locationStartsWith(E2eSeed.REDIRECT_URI)).as(signedIn + "\n" + browser.trail(10)).isTrue();
        final OidcFlow oidc = new OidcFlow(browser, realm);
        final OidcFlow.Tokens tokens = oidc.exchangeCode("web", web.secret(), E2eSeed.REDIRECT_URI,
                OidcFlow.query(signedIn.location()).get("code"), pkce.verifier());
        return oidc.verify(tokens.idToken()).getSubject();
    }

    /** A wallet-only sign-in that does not reach the client: the page it ends on. */
    private E2eHttp.Response walletSignInLanding(final String providerAlias, final Map<String, Object> pid) {
        final E2eHttp browser = newBrowser();
        final String next = walletLoginNext(browser, OidcFlow.Pkce.create(), providerAlias, pid);
        final E2eHttp.Response landed = browser.followRedirects(browser.get(next));
        assertThat(landed.status()).isEqualTo(200);
        return landed;
    }

    private String walletLoginNext(final E2eHttp browser, final OidcFlow.Pkce pkce, final String providerAlias,
                                   final Map<String, Object> pid) {
        browser.followRedirects(browser.get("/realms/" + realm + "/oauth2/authorize?response_type=code&client_id=web"
                + "&redirect_uri=" + E2eSeed.REDIRECT_URI + "&scope=openid%20profile&state=st&code_challenge="
                + pkce.challenge() + "&code_challenge_method=S256", "Accept", "text/html"));
        final E2eHttp.Response start = browser.get("/realms/" + realm + "/broker/" + providerAlias);
        final URI location = start.location();
        final String pageLocation = location.getPath() + "?" + location.getRawQuery();
        final String page = browser.get(pageLocation).body();
        assertThat(page).contains("Sign in with your EUDI Wallet");
        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(page));
        assertThat(wallet.respond(phone, request, pid).status()).isEqualTo(200);
        final JsonNode polled = browser.get(pageLocation.substring(0, pageLocation.indexOf('?')) + "/status?"
                + location.getRawQuery(), "Accept", "application/json").json();
        final String next = polled.path("next").asText();
        assertThat(next).contains("/broker/" + providerAlias + "/callback?response_code=");
        return next;
    }

    private String tupleOf(final Map<String, Object> pid) {
        return ((WalletSubject.Tuple) context.getBean(WalletSubjectResolver.class)
                .resolve(realm, matched(pid), provider.config())).value();
    }

    private WalletSubject.AdminNumber numberSubject(final String number) {
        final WalletSubject.AdminNumber resolved = (WalletSubject.AdminNumber) context
                .getBean(WalletSubjectResolver.class)
                .resolve(realm, matched(WalletE2eFixture.pidWithNumber(number)), provider.config());
        return new WalletSubject.AdminNumber(resolved.value(), null);
    }

    private long countWalletAccounts() {
        return context.getBean(org.springframework.jdbc.core.JdbcTemplate.class).queryForObject(
                "SELECT count(*) FROM user_credentials WHERE realm_id = ? AND password IS NULL", Long.class, realm);
    }

    private static MatchedPresentations matched(final Map<String, Object> claims) {
        return new MatchedPresentations(List.of(new VerifiedPresentation("dc+sd-jwt", "urn:eudi:pid:1",
                Map.copyOf(claims), "CN=issuer", "01", "VALID")), Set.of());
    }
}
