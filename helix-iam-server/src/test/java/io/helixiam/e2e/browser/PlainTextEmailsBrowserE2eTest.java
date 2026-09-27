/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.microsoft.playwright.Locator;
import io.helixiam.authorization.messaging.MessagingService;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.service.account.EmailChangeService;
import io.helixiam.authorization.service.emailverification.EmailVerificationMessage;
import io.helixiam.authorization.service.emailverification.RealmEmailVerificationSender;
import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;

import java.util.Locale;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Item 3: every email the server sends is usable as plain text. The HTTP email API receives a {@code text} part next to
 * the HTML, and it carries the link (and for registration and reset the code) in the user's language: registration and
 * reset driven from a real browser (English and Dutch), the admin's verification email, the account console's email
 * change, the magic link and the one-time code through the same senders the server uses.
 */
class PlainTextEmailsBrowserE2eTest extends AbstractBrowserE2eTest {

    @Test
    void registration_andReset_haveTheLinkAndTheCodeInTheTextPart_inTheUsersLanguage() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());

        final String email = register(realm, "");
        final MailSink.CapturedEmail verify = readCapturedEmail(email, "/register/verify/");
        final String link = verify.link(realm.path() + "/register/verify/").orElseThrow();
        final String code = link.substring(link.lastIndexOf('/') + 1);
        assertPlainText(verify, "registration");
        assertThat(verify.text()).as("registration").contains("Confirm email address:\n" + link)
                .contains("Or enter this code on the confirmation page:\n" + code)
                .contains(baseUrl() + realm.path() + "/register/verify\n");

        final String dutch = register(realm, "?lang=nl");
        final MailSink.CapturedEmail nl = readCapturedEmail(dutch, "/register/verify/");
        assertPlainText(nl, "registration (nl)");
        assertThat(nl.text()).as("registration (nl)")
                .contains("E-mailadres bevestigen:\n" + nl.link("/register/verify/").orElseThrow())
                .contains("Of vul deze code in op de bevestigingspagina:").contains("Verstuurd door").doesNotContain("Confirm");
        page().navigate(baseUrl() + realm.path() + "/reset/password?lang=en");

        final E2eSeed.SeededUser joe = seed().user(realm.realm(), E2eSeed.unique("joe") + "@monthfold.test",
                "Reset-Me-Passw0rd-2026!");
        page().navigate(baseUrl() + realm.path() + "/reset/password");
        page().locator("#username").fill(joe.username());
        submit(page().locator("#passwordReset button[type=submit]"));
        final MailSink.CapturedEmail reset = readCapturedEmail(joe.username(), "/reset/password/");
        final String resetLink = reset.link(realm.path() + "/reset/password/").orElseThrow();
        assertPlainText(reset, "reset");
        assertThat(reset.text()).as("reset").contains("Choose a new password:\n" + resetLink)
                .contains("Your reset code:\n" + resetLink.substring(resetLink.lastIndexOf('/') + 1));
    }

    @Test
    void adminVerification_emailChange_magicLink_andCode_haveTheirLinkOrCodeInTheTextPart_inEnglishAndDutch() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eSeed.SeededUser ada = seed().user(realm.realm(), E2eSeed.unique("ada"), "Plain-Text-Passw0rd-2026!");
        final String verifyLink = baseUrl() + realm.path() + "/verify-email?token=v3r1fy";
        final String changeBase = baseUrl() + realm.path();

        for (final Locale locale : new Locale[] {Locale.ENGLISH, Locale.forLanguageTag("nl-NL")}) {
            final boolean dutch = "nl".equals(locale.getLanguage());
            final String inbox = E2eSeed.unique("plain-" + locale.getLanguage()) + "@monthfold.test";
            RealmContextHolder.set(realm.realm());
            LocaleContextHolder.setLocale(locale);
            try {
                assertThat(context.getBean(RealmEmailVerificationSender.class).send(new EmailVerificationMessage(
                        realm.realm(), ada.userId(), inbox, verifyLink, 24))).isTrue();
                context.getBean(EmailChangeService.class).sendLink(realm.realm(), ada.userId(), inbox, changeBase);
                final MessagingService messaging = context.getBean(MessagingService.class);
                assertThat(messaging.sendEmail(realm.realm(), inbox, "magic-link-email", Map.of("realm", realm.realm(),
                        "link", changeBase + "/login/magic/verify?token=m4g1c", "user", "Ada",
                        "ttl", dutch ? "15 minuten" : "15 minutes"))).isTrue();
                assertThat(messaging.sendEmail(realm.realm(), inbox, "otp-email", Map.of("realm", realm.realm(),
                        "code", "481516", "ttl", dutch ? "5 minuten" : "5 minutes", "user", "Ada"))).isTrue();
            } finally {
                RealmContextHolder.clear();
                LocaleContextHolder.resetLocaleContext();
            }

            final MailSink.CapturedEmail admin = readCapturedEmail(inbox, "/verify-email?token=");
            assertPlainText(admin, "admin verification " + locale);
            assertThat(admin.text()).contains(verifyLink).contains(dutch ? "24 uur" : "24 hours");

            final MailSink.CapturedEmail change = readCapturedEmail(inbox, "/account/email/verify?token=");
            assertPlainText(change, "email change " + locale);
            assertThat(change.text()).contains(change.link("/account/email/verify?token=").orElseThrow());

            final MailSink.CapturedEmail magic = readCapturedEmail(inbox, "m4g1c");
            assertPlainText(magic, "magic link " + locale);
            assertThat(magic.text()).contains(changeBase + "/login/magic/verify?token=m4g1c");

            final MailSink.CapturedEmail otp = readCapturedEmail(inbox, "481516");
            assertPlainText(otp, "code " + locale);
            assertThat(otp.text()).contains("481516");

            for (final MailSink.CapturedEmail mail : new MailSink.CapturedEmail[] {admin, change, magic, otp}) {
                if (dutch) {
                    assertThat(mail.text()).as(mail.subject()).contains("Verstuurd door").contains("Hoi")
                            .doesNotContain("Hi ").doesNotContain("expires");
                } else {
                    assertThat(mail.text()).as(mail.subject()).contains("Sent by").doesNotContain("Hoi");
                }
            }
        }
    }

    private String register(final ReferenceSetup.Realm realm, final String query) {
        final String email = E2eSeed.unique("plain") + "@monthfold.test";
        page().navigate(baseUrl() + realm.path() + "/register" + query);
        page().locator("#username").fill(email);
        final Locator required = page().locator("#loginForm input[required]");
        for (int i = 0; i < required.count(); i++) {
            required.nth(i).fill("Test");
        }
        page().locator("#username").fill(email);
        page().locator("#password").fill(RegistrationVerificationBrowserE2eTest.PASSWORD);
        page().locator("#repeatPassword").fill(RegistrationVerificationBrowserE2eTest.PASSWORD);
        submit(page().locator("#loginForm button[type=submit]"));
        return email;
    }

    /** An HTML email with a plain-text part: no markup, nothing that asks for an HTML email app. */
    private static void assertPlainText(final MailSink.CapturedEmail mail, final String which) {
        assertThat(mail.html()).as(which).isTrue();
        assertThat(mail.text()).as(which + ": a text part").isNotBlank().doesNotContain("<").doesNotContain("&amp;")
                .doesNotContainIgnoringCase("shows HTML");
    }
}
