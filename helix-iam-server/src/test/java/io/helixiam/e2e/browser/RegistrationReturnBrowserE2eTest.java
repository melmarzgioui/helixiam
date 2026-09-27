/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import io.helixiam.e2e.E2eHttp;
import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Item A8: after registration or verification the user goes back to the pending authorization request (they used to
 * land on {@code spBaseUrl}, the IdP host); without one, to the realm's {@code postRegistrationRedirectUrl}, which
 * must be one of the realm's registered redirect origins.
 *
 * <p>Done when: a browser starts at the app, registers from the login link, verifies from the email, and ends back
 * at the app's callback (here with the reference realm's required two-step enrolment on the way).
 */
class RegistrationReturnBrowserE2eTest extends AbstractBrowserE2eTest {

    @Test
    void registerFromTheAppsSignIn_verifyFromTheEmail_andEndBackAtTheAppsCallback() {
        final ReferenceSetup.Realm realm = referenceRealm();
        final String email = E2eSeed.unique("signup") + "@monthfold.test";

        startSignInAtRp(realm.web());
        registerFromTheLoginPage(email);
        // The success page continues the pending sign-in (not spBaseUrl).
        assertThat(page().locator("a.continueLogin").getAttribute("href")).contains(realm.path() + "/oauth2/authorize");

        final String link = verifyLink(readCapturedEmail(email), realm);
        page().navigate(link);

        // Back in the pending sign-in: the login page says the address is verified and knows who is signing in.
        assertOnIdpPath("/login");
        assertThat(page().locator("[role=status]").first().innerText()).containsIgnoringCase("verified");
        assertThat(page().locator("#username").inputValue()).isEqualTo(email);
        page().locator("#password").fill(RegistrationVerificationBrowserE2eTest.PASSWORD);
        submit(page().locator("#loginForm button[type=submit]"));
        completeTotpEnrolment();

        final TestRelyingParty.Callback callback = assertLandedOnRpCallback();
        assertThat(callback.code()).isNotBlank();
        assertThat(callback.idTokenClaims().getClaim("email")).isEqualTo(email);
        assertThat(cspViolations()).as(describeBrowser()).isEmpty();
    }

    @Test
    void withoutAPendingSignIn_verificationGoesToTheRealmsPostRegistrationRedirectUrl() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final String welcome = rp().postLogoutUri();
        final E2eHttp.Response set = adminSession().put("/admin/realms/" + realm.realm() + "/settings/registration",
                Map.of("postRegistrationRedirectUrl", welcome));
        assertThat(set.status()).as(set.toString()).isEqualTo(200);
        assertThat(set.json().path("postRegistrationRedirectUrl").asText()).isEqualTo(welcome);

        final String email = E2eSeed.unique("elsewhere") + "@monthfold.test";
        page().navigate(baseUrl() + realm.path() + "/register");
        fillAndSubmitRegistration(email);
        assertThat(page().locator("a.continueLogin").getAttribute("href")).isEqualTo(welcome);
        final String link = verifyLink(readCapturedEmail(email), realm);

        // The link opened in another browser (no pending sign-in): the realm's landing page on the app.
        clearCookies();
        page().navigate(link);
        assertThat(page().url()).isEqualTo(welcome);
        assertThat(rp().landings()).hasSize(1);
    }

    @Test
    void withoutEither_verificationGoesToTheRealmsLoginPage() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final String email = E2eSeed.unique("plain") + "@monthfold.test";
        page().navigate(baseUrl() + realm.path() + "/register");
        fillAndSubmitRegistration(email);
        assertThat(page().locator("a.continueLogin").getAttribute("href")).endsWith(realm.path() + "/login");
        page().navigate(verifyLink(readCapturedEmail(email), realm));
        assertOnIdpPath("/login");
        assertThat(page().locator("[role=status]").first().innerText()).containsIgnoringCase("verified");
    }

    @Test
    void thePostRegistrationRedirectUrl_mustBeOnARegisteredRedirectOrigin() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final String path = "/admin/realms/" + realm.realm() + "/settings/registration";
        for (final String bad : new String[] {"https://evil.example/", "javascript:alert(1)", "/relative",
                rp().origin().replace("127.0.0.1", "127.0.0.2") + "/"}) {
            final E2eHttp.Response r = adminSession().put(path, Map.of("postRegistrationRedirectUrl", bad));
            assertThat(r.status()).as(bad + " → " + r).isEqualTo(400);
            assertThat(r.json().path("fieldErrors").path("postRegistrationRedirectUrl").asText()).isNotBlank();
        }
        // Any path on a registered origin is fine; an empty value clears it.
        assertThat(adminSession().put(path, Map.of("postRegistrationRedirectUrl", rp().origin() + "/dashboard?x=1"))
                .status()).isEqualTo(200);
        final Map<String, Object> clear = new HashMap<>();
        clear.put("postRegistrationRedirectUrl", "");
        final E2eHttp.Response cleared = adminSession().put(path, clear);
        assertThat(cleared.status()).isEqualTo(200);
        assertThat(cleared.json().path("postRegistrationRedirectUrl").isNull()).isTrue();
        assertThat(adminSession().get(path).json().path("postRegistrationRedirectUrl").isNull()).isTrue();
    }

    // ------------------------------------------------------------------------------------------------

    private void registerFromTheLoginPage(final String email) {
        assertOnIdpPath("/login");
        submit(page().locator(".subtext a[href$='/register']"));
        assertOnIdpPath("/register");
        fillAndSubmitRegistration(email);
    }

    private void fillAndSubmitRegistration(final String email) {
        page().locator("#username").fill(email);
        final com.microsoft.playwright.Locator required = page().locator("#loginForm input[required]");
        for (int i = 0; i < required.count(); i++) {
            required.nth(i).fill("Test");
        }
        page().locator("#password").fill(RegistrationVerificationBrowserE2eTest.PASSWORD);
        page().locator("#repeatPassword").fill(RegistrationVerificationBrowserE2eTest.PASSWORD);
        submit(page().locator("#loginForm button[type=submit]"));
        assertThat(page().locator(".actionSuccess").count()).as(describeBrowser()).isEqualTo(1);
    }

    private String verifyLink(final MailSink.CapturedEmail mail, final ReferenceSetup.Realm realm) {
        return RegistrationVerificationBrowserE2eTest.verifyLink(mail, realm);
    }
}
