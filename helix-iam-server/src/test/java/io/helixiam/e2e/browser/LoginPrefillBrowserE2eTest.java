/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The login page's username field is filled in for the user: from the RP's {@code login_hint} (item E3), and with
 * what they typed after a failed sign-in (so only the password has to be typed again).
 */
class LoginPrefillBrowserE2eTest extends AbstractBrowserE2eTest {

    private static final String PASSWORD = "Prefill-Passw0rd-2026!";

    @Test
    void theRpsLoginHint_prefillsTheEmail_andTheSignInCompletes() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eSeed.SeededUser joe = seed().user(realm.realm(), E2eSeed.unique("joe") + "@monthfold.test", PASSWORD);

        startSignInAtRp(realm.web(), Map.of("login_hint", joe.username()));

        assertOnIdpPath("/login");
        assertThat(page().locator("#username").inputValue()).isEqualTo(joe.username());
        page().locator("#password").fill(PASSWORD);
        submit(page().locator("#loginForm button[type=submit]"));
        assertThat(assertLandedOnRpCallback().subject()).isEqualTo(joe.userId());
    }

    @Test
    void anOverlongOrControlCharacterHint_isIgnored() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        startSignInAtRp(realm.web(), Map.of("login_hint", "a".repeat(300) + "@monthfold.test"));
        assertThat(page().locator("#username").inputValue()).isEmpty();
        startSignInAtRp(realm.web(), Map.of("login_hint", "joe\u0000@monthfold.test"));
        assertThat(page().locator("#username").inputValue()).isEmpty();
    }

    @Test
    void afterAFailedSignIn_theUsernameIsStillFilledIn_andThePasswordIsNot() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eSeed.SeededUser joe = seed().user(realm.realm(), E2eSeed.unique("joe") + "@monthfold.test", PASSWORD);

        startSignInAtRp(realm.web());
        signInWithPassword(joe.username(), "not-the-password");

        assertOnIdpPath("/login");
        assertThat(page().url()).as("the username is not put in the URL").doesNotContain("monthfold.test");
        assertThat(page().locator("#credentials-error").isVisible()).isTrue();
        assertThat(page().locator("#username").inputValue()).isEqualTo(joe.username());
        assertThat(page().locator("#password").inputValue()).isEmpty();

        // Only once: a fresh visit of the login page starts empty again.
        page().navigate(baseUrl() + realm.path() + "/login");
        assertThat(page().locator("#username").inputValue()).isEmpty();

        // And the retry completes the pending sign-in.
        startSignInAtRp(realm.web());
        signInWithPassword(joe.username(), "not-the-password");
        page().locator("#password").fill(PASSWORD);
        submit(page().locator("#loginForm button[type=submit]"));
        assertThat(assertLandedOnRpCallback().subject()).isEqualTo(joe.userId());
    }
}
