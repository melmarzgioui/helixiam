/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import io.helixiam.authorization.messaging.MessagingService;
import io.helixiam.e2e.E2eHttp;
import io.helixiam.e2e.E2eSeed;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Structured theming Task 4: every email a realm sends — verification, password reset, magic link and the one-time
 * code — carries the realm theme's logo, colours, footer text and links, not HelixIAM's, through the realm's own email
 * provider. Registration and reset are driven from a real browser; the magic link and code emails are sent through
 * the same {@link MessagingService} path the sign-in uses (the e2e context captures magic links before they reach the
 * provider).
 */
class ThemedEmailsBrowserE2eTest extends AbstractBrowserE2eTest {

    private static final String LOGO = "https://cdn.monthfold.example/logo.png";

    private static Map<String, Object> monthfoldTheme() {
        return Map.of(
                "colors", Map.of("primary", Map.of("light", "#1f4d47", "dark", "#7fb8ac"),
                        "surface", Map.of("light", "#f7f8f6", "dark", "#111615"),
                        "surfaceRaised", Map.of("light", "#ffffff", "dark", "#192120"),
                        "ink", Map.of("light", "#16211f", "dark", "#e8eeec"),
                        "inkMuted", Map.of("light", "#56635f", "dark", "#a3b0ac")),
                "assets", Map.of("logoUrl", LOGO),
                "texts", Map.of("footerText", "© Monthfold BV, Utrecht"),
                "links", Map.of("privacyUrl", "https://monthfold.example/privacy",
                        "termsUrl", "https://monthfold.example/terms"));
    }

    @Test
    void verification_reset_magicLink_andCodeEmails_allCarryTheRealmTheme() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eHttp.Response themed = adminSession().put("/admin/realms/" + realm.realm() + "/theme", monthfoldTheme());
        assertThat(themed.status()).as(themed.toString()).isEqualTo(200);

        // Verification: register in the browser.
        final String email = E2eSeed.unique("themed") + "@monthfold.test";
        page().navigate(baseUrl() + realm.path() + "/register");
        page().locator("#username").fill(email);
        final com.microsoft.playwright.Locator required = page().locator("#loginForm input[required]");
        for (int i = 0; i < required.count(); i++) {
            required.nth(i).fill("Test");
        }
        page().locator("#password").fill(RegistrationVerificationBrowserE2eTest.PASSWORD);
        page().locator("#repeatPassword").fill(RegistrationVerificationBrowserE2eTest.PASSWORD);
        submit(page().locator("#loginForm button[type=submit]"));
        assertThemed(readCapturedEmail(email, "/register/verify/"), "verification");

        // Reset: request it in the browser for a seeded user.
        final E2eSeed.SeededUser joe = seed().user(realm.realm(), E2eSeed.unique("joe") + "@monthfold.test",
                "Reset-Me-Passw0rd-2026!");
        page().navigate(baseUrl() + realm.path() + "/reset/password");
        page().locator("#username").fill(joe.username());
        submit(page().locator("#passwordReset button[type=submit]"));
        final MailSink.CapturedEmail reset = readCapturedEmail(joe.username(), "/reset/password/");
        assertThemed(reset, "reset");
        assertThat(reset.link(realm.path() + "/reset/password/")).as("a link to the realm's reset page").isPresent();

        // Magic link and one-time code: the realm's templates through its provider.
        final MessagingService messaging = context.getBean(MessagingService.class);
        final String inbox = E2eSeed.unique("magic") + "@monthfold.test";
        RealmContextHolder.set(realm.realm());
        try {
            assertThat(messaging.sendEmail(realm.realm(), inbox, "magic-link-email", Map.of("realm", "Monthfold",
                    "link", baseUrl() + realm.path() + "/login/magic/verify?token=t", "ttl", "15 minutes", "user", "Ada")))
                    .isTrue();
            assertThat(messaging.sendEmail(realm.realm(), inbox, "otp-email", Map.of("realm", "Monthfold",
                    "code", "123456", "ttl", "5 minutes", "user", "Ada"))).isTrue();
        } finally {
            RealmContextHolder.clear();
        }
        assertThemed(readCapturedEmail(inbox, "login/magic/verify"), "magic link");
        assertThemed(readCapturedEmail(inbox, "123456"), "one-time code", false);
    }

    private static void assertThemed(final MailSink.CapturedEmail mail, final String which) {
        assertThemed(mail, which, true);
    }

    /** {@code button}: the email has a call-to-action button (in the theme's primary colour); the code email has none. */
    private static void assertThemed(final MailSink.CapturedEmail mail, final String which, final boolean button) {
        assertThat(mail.html()).as(which).isTrue();
        assertThat(mail.body()).as(which + ": logo").contains("src=\"" + LOGO + "\"");
        if (button) {
            assertThat(mail.body()).as(which + ": button / primary colour").contains("bgcolor=\"#1f4d47\"");
        }
        assertThat(mail.body()).as(which + ": background").contains("background-color:#f7f8f6");
        assertThat(mail.body()).as(which + ": text colour").contains("color:#16211f");
        assertThat(mail.body()).as(which + ": footer").contains("© Monthfold BV, Utrecht");
        assertThat(mail.body()).as(which + ": links").contains("href=\"https://monthfold.example/privacy\"")
                .contains("href=\"https://monthfold.example/terms\"");
        for (final String helix : List.of("HelixIAM", "#f6f1e9", "#2f6b52")) {
            assertThat(mail.body()).as(which + ": no HelixIAM look (" + helix + ")").doesNotContain(helix);
        }
        assertThat(mail.subject()).as(which).doesNotContain("HelixIAM");
    }
}
