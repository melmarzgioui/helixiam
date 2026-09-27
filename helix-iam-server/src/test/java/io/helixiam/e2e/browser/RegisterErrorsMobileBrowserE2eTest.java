/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.microsoft.playwright.options.BoundingBox;
import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * On a phone (390 × 844), a registration refused because the passwords do not match says so at the top of the page,
 * in view without scrolling, and the password fields point to that message.
 */
class RegisterErrorsMobileBrowserE2eTest extends AbstractBrowserE2eTest {

    @Test
    void aPasswordMismatch_isAnnouncedAtTheTop_inViewOnAPhone() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        page().setViewportSize(390, 844);
        page().navigate(baseUrl() + realm.path() + "/register");
        page().locator("#username").fill(E2eSeed.unique("phone") + "@monthfold.test");
        final com.microsoft.playwright.Locator required = page().locator("#loginForm input[required]");
        for (int i = 0; i < required.count(); i++) {
            required.nth(i).fill("Test");
        }
        page().locator("#password").fill("Mismatch-Passw0rd-1!");
        page().locator("#repeatPassword").fill("Mismatch-Passw0rd-2!");
        submit(page().locator("#loginForm button[type=submit]"));

        assertThat(page().evaluate("() => window.scrollY")).isEqualTo(0);
        final BoundingBox alert = page().locator("#password-error").boundingBox();
        assertThat(alert).as("the mismatch alert is rendered").isNotNull();
        assertThat(alert.y + alert.height).as("the alert is in view without scrolling").isLessThanOrEqualTo(844);
        final BoundingBox title = page().locator(".form-head h2").boundingBox();
        assertThat(alert.y).as("under the title").isGreaterThan(title.y);
        assertThat(page().locator("#password").getAttribute("aria-describedby")).isEqualTo("password-error");
        assertThat(page().locator("#password-error").getAttribute("role")).isEqualTo("alert");
    }
}
