/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Item A1 ("sign-in never returns to the app after the two-step code"), Done when: a browser signs in with
 * password + TOTP to a relying party on another origin and lands on its callback with a code.
 *
 * <p>Cause today: every auth page sends {@code form-action 'self'}, and Chrome applies it to the whole redirect
 * chain after a form POST, so {@code POST /mfa/totp} → {@code 302 /oauth2/authorize} → {@code 302
 * http://127.0.0.1:<rp>/auth/callback} is blocked and the user stays on the code page. Chrome reports (captured
 * by the harness before this test was disabled):
 * <pre>
 * Sending form data to 'http://localhost:&lt;idp&gt;/realms/&lt;realm&gt;/mfa/totp' violates the following Content Security
 * Policy directive: "form-action 'self'". The request has been blocked.
 * requestfailed: GET …/oauth2/authorize?…&amp;continue -&gt; net::ERR_ABORTED
 * </pre>
 * Enable it with the A1 fix.
 */
class CrossOriginSignInBrowserE2eTest extends AbstractBrowserE2eTest {

    private static final String PASSWORD = "Cross-Origin-Passw0rd!";

    @Test
    @Disabled("A1: CSP form-action blocks cross-origin redirect after POST — fixed in the A1 commit")
    void passwordAndTotp_landOnTheRpCallbackWithACode() {
        final ReferenceSetup.Realm realm = referenceRealm();
        final E2eSeed.SeededUser joe = seed().user(realm.realm(), E2eSeed.unique("joe"), PASSWORD);

        // First sign-in enrols the authenticator (its last hop follows a GET link, so it is not the case under test).
        startSignInAtRp(realm.web());
        signInWithPassword(joe.username(), joe.password());
        final TotpDevice device = completeTotpEnrolment();
        clearCookies();
        rp().reset();

        // The everyday sign-in: password, then the two-step code, then back at the app.
        startSignInAtRp(realm.web());
        signInWithPassword(joe.username(), joe.password());
        enterTotp(device);

        final TestRelyingParty.Callback callback = assertLandedOnRpCallback();
        assertThat(callback.code()).isNotBlank();
        assertThat(callback.subject()).isEqualTo(joe.userId());
        assertThat(cspViolations()).as(describeBrowser()).noneMatch(v -> v.contains("form-action"));
    }
}
