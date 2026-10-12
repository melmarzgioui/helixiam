/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.microsoft.playwright.APIResponse;
import com.microsoft.playwright.Locator;
import io.helixiam.authorization.federation.wallet.testwallet.Oid4vpWalletClient;
import io.helixiam.e2e.E2eHttp;
import io.helixiam.e2e.E2eSeed;
import io.helixiam.e2e.WalletE2eFixture;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Task 18: "Sign in with EUDI Wallet" in a real browser. The login page offers the wallet, the wallet page renders
 * under the strict page CSP (no inline script or style, the QR code an SVG {@code data:} image), and its polling script
 * completes the login on its own once the test wallet has posted a presentation from "another device".
 */
class WalletLoginBrowserE2eTest extends AbstractBrowserE2eTest {

    @Test
    void walletPage_rendersUnderTheStrictCsp_andPollingCompletesTheLogin() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final WalletE2eFixture wallet = new WalletE2eFixture(context);
        final String alias = E2eSeed.unique("eudi");
        wallet.install(wallet.storedProvider(realm.realm(), alias, Map.of()));

        startSignInAtRp(realm.web());
        assertOnIdpPath("/login");
        final Locator button = page().locator("a.federationProvider.idp-eudi-wallet");
        assertThat(button.locator("img.fed-logo").getAttribute("src")).contains("/img/idp/eudi-wallet").endsWith(".svg");
        button.click();
        page().waitForURL(url -> url.contains("/broker/" + alias + "/wallet?tx="));

        // The page's own response: the login CSP plus data: images (the QR) and same-origin fetches (the poll).
        final APIResponse self = page().context().request().get(page().url());
        final String csp = self.headers().get("content-security-policy");
        assertThat(csp).doesNotContain("unsafe-inline").doesNotContain("unsafe-eval")
                .contains("img-src 'self' data:").contains("connect-src 'self'").contains("script-src 'self'")
                .contains("style-src 'self'");
        assertThat(((Number) page().evaluate("document.querySelectorAll('[style]').length")).intValue())
                .as("no inline style attributes").isZero();
        assertThat(((Number) page().evaluate("document.querySelectorAll('style').length")).intValue())
                .as("no <style> blocks").isZero();
        assertThat(((Number) page().evaluate("[...document.scripts].filter(s => !s.src).length")).intValue())
                .as("no inline <script>").isZero();
        assertThat(page().locator("#walletQr").getAttribute("src")).startsWith("data:image/svg+xml;base64,");
        assertThat(page().locator("#walletQr").isVisible()).isTrue();
        assertThat(page().locator("#walletStatus").getAttribute("aria-live")).isEqualTo("polite");
        assertThat(page().locator("#walletOpen").getAttribute("href")).startsWith("haip-vp://?client_id=");
        shots("wallet-page");

        // The phone scans the QR code shown in this browser and answers.
        final E2eHttp phone = new E2eHttp(baseUrl());
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(page().content()));
        assertThat(wallet.respond(phone, request, WalletE2eFixture.pidWithNumber("PAN-" + UUID.randomUUID())).status())
                .isEqualTo(200);

        // No click: the page's polling script notices and finishes the sign-in.
        page().waitForURL(url -> url.startsWith(rp().callbackUri() + "?"));
        assertThat(assertLandedOnRpCallback().subject()).isNotBlank();
        assertThat(cspViolations()).as(describeBrowser()).isEmpty();
    }

    @Test
    void aFailedWalletResponse_showsTheRetry() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final WalletE2eFixture wallet = new WalletE2eFixture(context);
        final String alias = E2eSeed.unique("eudi");
        wallet.install(wallet.storedProvider(realm.realm(), alias, Map.of()));
        startSignInAtRp(realm.web());
        page().navigate(baseUrl() + realm.path() + "/broker/" + alias);
        page().waitForURL(url -> url.contains("/wallet?tx="));
        assertThat(page().locator("#walletRetry").isVisible()).isFalse();

        final E2eHttp phone = new E2eHttp(baseUrl());
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(page().content()));
        phone.postForm(request.responseUri(), Map.of("error", "access_denied", "state", request.state()));

        page().locator("#walletRetry").waitFor();
        assertThat(page().locator("#walletRetry").isVisible()).isTrue();
        assertThat(page().locator("#walletStatus").textContent()).containsIgnoringCase("try again");
        shots("wallet-page-failed");
        assertThat(cspViolations()).as(describeBrowser()).isEmpty();
    }
}
