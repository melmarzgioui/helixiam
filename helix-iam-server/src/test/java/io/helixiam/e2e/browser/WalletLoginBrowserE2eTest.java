/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.microsoft.playwright.APIResponse;
import com.microsoft.playwright.Locator;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.federation.spi.IdpMetadata;
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
        // The wallet next to the built-in eID marks, as a realm with DigiD and eIDAS would show it.
        wallet.install(realm.realm(), wallet.storedProvider(realm.realm(), alias, Map.of()), neighbour("digid", "DigiD"),
                neighbour("eidas", "eIDAS"));

        startSignInAtRp(realm.web());
        assertOnIdpPath("/login");
        shots("login-with-wallet");
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

        // The phone scans the QR code shown in this browser: the page notices the wallet opened the request.
        final E2eHttp phone = new E2eHttp(baseUrl());
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(page().content()));
        page().waitForCondition(() -> page().locator("#walletStatus").textContent().contains("Wallet opened"));
        assertThat(page().locator("#walletActive").isVisible()).as("the spent QR code is put away").isFalse();
        shots("wallet-page-opened");
        // ...and answers.
        assertThat(wallet.respond(phone, request, WalletE2eFixture.pidWithNumber("PAN-" + UUID.randomUUID())).status())
                .isEqualTo(200);

        // No click: the page's polling script notices and finishes the sign-in.
        page().waitForURL(url -> url.startsWith(rp().callbackUri() + "?"));
        assertThat(assertLandedOnRpCallback().subject()).isNotBlank();
        assertThat(cspViolations()).as(describeBrowser()).isEmpty();
    }

    /** Mobile: the same-device "Open wallet app" is the first and primary action; the QR code comes below it. */
    @Test
    void onAPhone_openWalletComesFirst_andTheQrCodeSecond() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final WalletE2eFixture wallet = new WalletE2eFixture(context);
        final String alias = E2eSeed.unique("eudi");
        wallet.install(realm.realm(), wallet.storedProvider(realm.realm(), alias, Map.of()));
        startSignInAtRp(realm.web());
        page().setViewportSize(390, 844);
        page().navigate(baseUrl() + realm.path() + "/broker/" + alias);
        page().waitForURL(url -> url.contains("/wallet?tx="));

        final double open = page().locator("#walletOpen").boundingBox().y;
        final double qr = page().locator("#walletQr").boundingBox().y;
        assertThat(open).as("Open wallet app above the QR code on a phone").isLessThan(qr);

        page().setViewportSize(1440, 900);
        assertThat(page().locator("#walletQr").boundingBox().x)
                .as("the QR code leads on a desktop").isLessThan(page().locator("#walletOpen").boundingBox().x);
    }

    @Test
    void aFailedWalletResponse_showsTheRetry() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final WalletE2eFixture wallet = new WalletE2eFixture(context);
        final String alias = E2eSeed.unique("eudi");
        wallet.install(realm.realm(), wallet.storedProvider(realm.realm(), alias, Map.of()));
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
        // the house error treatment, announced assertively, and the keyboard lands on the retry
        assertThat(page().locator("#walletStatus").getAttribute("class")).contains("hx-alert").contains("hx-alert-error");
        assertThat(page().locator("#walletStatus").getAttribute("role")).isEqualTo("alert");
        assertThat(page().evaluate("document.activeElement && document.activeElement.id")).isEqualTo("walletRetry");
        shots("wallet-page-failed");
        assertThat(cspViolations()).as(describeBrowser()).isEmpty();
    }

    /** A stand-in provider that only shows a built-in eID mark on the login page (never started here). */
    private static IdentityProvider neighbour(final String iconKey, final String name) {
        final IdpMetadata metadata = IdpMetadata.of(E2eSeed.unique(iconKey), IdpMetadata.Protocol.SAML2, name, iconKey,
                null);
        return new IdentityProvider() {
            @Override
            public IdpMetadata metadata() {
                return metadata;
            }

            @Override
            public RedirectResponse start(final AuthnRequestContext context) {
                throw new UnsupportedOperationException();
            }

            @Override
            public io.helixiam.authorization.federation.spi.BrokeredIdentity callback(final CallbackContext context) {
                throw new UnsupportedOperationException();
            }

            @Override
            public void logout(final LogoutContext context) {
            }
        };
    }
}
