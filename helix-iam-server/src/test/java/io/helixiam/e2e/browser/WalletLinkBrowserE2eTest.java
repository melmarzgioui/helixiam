/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.microsoft.playwright.Locator;
import io.helixiam.authorization.federation.wallet.testwallet.Oid4vpWalletClient;
import io.helixiam.e2e.E2eHttp;
import io.helixiam.e2e.E2eSeed;
import io.helixiam.e2e.WalletE2eFixture;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Task 21b: "Link EU Digital Identity Wallet" in a real browser. The user signs in with a password, opens the account
 * console, links the wallet (the test wallet answers from "another device" while the wallet page polls), signs out, and
 * then signs in at the application with the wallet only, landing on the same account. The console section, the link
 * refusals and the improved "link your wallet first" page render under the strict CSP.
 */
class WalletLinkBrowserE2eTest extends AbstractBrowserE2eTest {

    private static final String PASSWORD = "Wallet-Link-Passw0rd-2026!";

    @Test
    void signInWithAPassword_linkTheWallet_signOut_thenAWalletOnlySignInLandsOnThatAccount() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final WalletE2eFixture wallet = new WalletE2eFixture(context);
        final String alias = E2eSeed.unique("eudi");
        wallet.install(realm.realm(), wallet.storedProvider(realm.realm(), alias, Map.of("subject.acknowledgeWeakSubject", "true")));
        final E2eSeed.SeededUser ada = seed().user(realm.realm(), E2eSeed.unique("ada"), PASSWORD,
                Map.of("given_name", "Ada", "family_name", "Lovelace"));

        // 1. Password sign-in, account console: the wallet is offered, not linked.
        page().navigate(baseUrl() + realm.path() + "/account");
        signInWithPassword(ada.username(), PASSWORD);
        assertOnIdpPath("/account");
        final Locator row = page().locator("#wallets li[data-alias='" + alias + "']");
        assertThat(row.innerText()).contains("EU Digital Identity Wallet").contains("Not linked");
        assertThat(row.locator("form input[name=_csrf]").count()).as("one CSRF field").isEqualTo(1);
        assertNoInlineStyleOrScript();
        page().locator("#wallets").scrollIntoViewIfNeeded();
        shots("link-console-unlinked");

        // 2. Link: the same wallet page, in link wording; the wallet answers from another device.
        submit(row.locator("button"));
        page().waitForURL(url -> url.contains("/broker/" + alias + "/wallet?tx="));
        assertThat(page().locator("h1").innerText()).isEqualTo("Link your EUDI Wallet");
        assertThat(page().locator("#walletBack").getAttribute("href")).endsWith(realm.path() + "/account");
        shots("link-wallet-page");
        final E2eHttp phone = new E2eHttp(baseUrl());
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(page().content()));
        assertThat(wallet.respond(phone, request, WalletE2eFixture.pidWithoutNumber()).status()).isEqualTo(200);

        // 3. The page's polling brings the browser back to the console: linked.
        page().waitForURL(url -> url.contains("/account") && !url.contains("/wallet"));
        assertOnIdpPath("/account");
        assertThat(page().locator("#wallet-status").innerText()).isEqualTo("Your wallet is linked.");
        assertThat(page().locator("#wallets li[data-alias='" + alias + "'] .hx-badge-ok").innerText())
                .isEqualTo("Linked");
        assertThat(page().locator("#wallets").innerText()).as("never the subject hash").doesNotMatch("(?s).*[0-9a-f]{64}.*");
        assertThat(page().locator("#wallets li[data-alias='" + alias + "'] a.hx-btn-danger").innerText())
                .isEqualTo("Unlink");
        assertThat(cspViolations()).as(describeBrowser()).isEmpty();
        shots("link-console-linked");

        // 4. Sign out, then sign in at the application with the wallet only.
        clearCookies();
        startSignInAtRp(realm.web());
        assertOnIdpPath("/login");
        page().locator("a.federationProvider.idp-eudi-wallet").click();
        page().waitForURL(url -> url.contains("/broker/" + alias + "/wallet?tx="));
        assertThat(page().locator("h1").innerText()).isEqualTo("Sign in with your EUDI Wallet");
        final Oid4vpWalletClient.VerifiedRequest login =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(page().content()));
        assertThat(wallet.respond(phone, login, WalletE2eFixture.pidWithoutNumber()).status()).isEqualTo(200);
        page().waitForURL(url -> url.startsWith(rp().callbackUri() + "?"));
        assertThat(assertLandedOnRpCallback().subject()).isEqualTo(ada.userId());
    }

    /** The refusals in the console section, and the improved "link your wallet first" page, for the UI review. */
    @Test
    void theRefusals_andTheLinkRequiredPage_explainWhatToDo() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final WalletE2eFixture wallet = new WalletE2eFixture(context);
        final String alias = E2eSeed.unique("eudi");
        final String strict = E2eSeed.unique("eudi-strict");
        wallet.install(realm.realm(), wallet.storedProvider(realm.realm(), alias, Map.of("subject.acknowledgeWeakSubject", "true")),
                wallet.storedProvider(realm.realm(), strict, Map.of()));
        final E2eSeed.SeededUser bob = seed().user(realm.realm(), E2eSeed.unique("bob"), PASSWORD);
        final E2eSeed.SeededUser ada = seed().user(realm.realm(), E2eSeed.unique("ada"), PASSWORD);
        final E2eHttp phone = new E2eHttp(baseUrl());

        // Bob links the wallet first.
        page().navigate(baseUrl() + realm.path() + "/account");
        signInWithPassword(bob.username(), PASSWORD);
        linkHere(wallet, phone, alias, WalletE2eFixture.pidWithoutNumber());
        assertThat(page().locator("#wallet-status").isVisible()).isTrue();
        clearCookies();

        // Ada: the same wallet is someone else's; which account is never said.
        page().navigate(baseUrl() + realm.path() + "/account");
        signInWithPassword(ada.username(), PASSWORD);
        linkHere(wallet, phone, alias, WalletE2eFixture.pidWithoutNumber());
        final Locator error = page().locator("#wallet-error");
        assertThat(error.innerText()).isEqualTo("This wallet is already linked to another account.");
        assertThat(error.getAttribute("role")).isEqualTo("alert");
        assertThat(page().content()).doesNotContain(bob.username());
        page().locator("#wallets").scrollIntoViewIfNeeded();
        shots("link-console-error-taken");

        // A provider that only links wallets with a number: refused with the reason.
        linkHere(wallet, phone, strict, WalletE2eFixture.pidWithoutNumber());
        assertThat(page().locator("#wallet-error").innerText()).contains("personal administrative number");
        assertNoInlineStyleOrScript();
        page().locator("#wallets").scrollIntoViewIfNeeded();
        shots("link-console-error-no-number");
        assertThat(cspViolations()).as(describeBrowser()).isEmpty();

        // Signed out, an unlinked wallet: the improved explanation, with no hint whether an account exists.
        clearCookies();
        startSignInAtRp(realm.web());
        final Map<String, Object> max = new LinkedHashMap<>(WalletE2eFixture.pidWithoutNumber());
        max.put("given_name", "Max");
        page().navigate(baseUrl() + realm.path() + "/broker/" + alias);
        page().waitForURL(url -> url.contains("/wallet?tx="));
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(page().content()));
        assertThat(wallet.respond(phone, request, max).status()).isEqualTo(200);
        page().waitForURL(url -> url.contains("/broker/" + alias + "/wallet/link"));
        assertThat(page().locator("h1").innerText()).isEqualTo("Link your wallet first");
        final Locator steps = page().locator("#walletLinkSteps li");
        assertThat(steps.count()).isEqualTo(3);
        assertThat(steps.nth(0).innerText()).contains("Sign in");
        assertThat(page().locator("#walletLinkSignIn").getAttribute("href")).endsWith(realm.path() + "/login");
        assertThat(page().content()).doesNotContain("Max").doesNotContain("Mustermann").doesNotContain(bob.username())
                .doesNotContainIgnoringCase("no account").doesNotContainIgnoringCase("not found");
        assertNoInlineStyleOrScript();
        shots("link-required-page");
        assertThat(cspViolations()).as(describeBrowser()).isEmpty();
    }

    /** On the console: Link → wallet page → the test wallet answers → back on the console. */
    private void linkHere(final WalletE2eFixture wallet, final E2eHttp phone, final String alias,
                          final Map<String, Object> pid) {
        assertOnIdpPath("/account");
        submit(page().locator("#wallets li[data-alias='" + alias + "'] button"));
        page().waitForURL(url -> url.contains("/broker/" + alias + "/wallet?tx="));
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(page().content()));
        assertThat(wallet.respond(phone, request, pid).status()).isEqualTo(200);
        page().waitForURL(url -> url.contains("/account") && !url.contains("/wallet"));
    }

    private void assertNoInlineStyleOrScript() {
        assertThat(((Number) page().evaluate("document.querySelectorAll('[style]').length")).intValue())
                .as("no inline style attributes").isZero();
        assertThat(((Number) page().evaluate("[...document.scripts].filter(s => !s.src).length")).intValue())
                .as("no inline <script>").isZero();
    }
}
