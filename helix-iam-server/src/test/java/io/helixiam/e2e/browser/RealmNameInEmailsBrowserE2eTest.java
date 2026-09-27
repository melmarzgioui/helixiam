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
import io.helixiam.authorization.service.magiclink.MagicLinkMessage;
import io.helixiam.authorization.service.magiclink.RealmMagicLinkSender;
import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Item 4: emails name the realm by its display name ("Monthfold"), never by its id ({@code monthfold-…}), in the
 * subject and the text. The id only appears inside links. Registration is driven from a real browser; the admin's
 * verification email, the email change, the magic link and the one-time code go through the senders the server uses,
 * which pass the realm id.
 */
class RealmNameInEmailsBrowserE2eTest extends AbstractBrowserE2eTest {

    @Test
    void everyEmail_namesTheRealmByItsDisplayName() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        assertThat(realm.displayName()).isEqualTo("Monthfold");
        assertThat(realm.realm()).isNotEqualTo("Monthfold");

        final String registered = E2eSeed.unique("named") + "@monthfold.test";
        page().navigate(baseUrl() + realm.path() + "/register");
        final Locator required = page().locator("#loginForm input[required]");
        for (int i = 0; i < required.count(); i++) {
            required.nth(i).fill("Test");
        }
        page().locator("#username").fill(registered);
        page().locator("#password").fill(RegistrationVerificationBrowserE2eTest.PASSWORD);
        page().locator("#repeatPassword").fill(RegistrationVerificationBrowserE2eTest.PASSWORD);
        submit(page().locator("#loginForm button[type=submit]"));
        assertNamed(readCapturedEmail(registered, "/register/verify/"), realm, "Confirm your email address for Monthfold");

        final E2eSeed.SeededUser ada = seed().user(realm.realm(), E2eSeed.unique("ada"), "Named-Realm-Passw0rd-2026!");
        final String inbox = E2eSeed.unique("named") + "@monthfold.test";
        RealmContextHolder.set(realm.realm());
        try {
            context.getBean(RealmEmailVerificationSender.class).send(new EmailVerificationMessage(realm.realm(),
                    ada.userId(), inbox, baseUrl() + realm.path() + "/verify-email?token=n4me", 24));
            context.getBean(EmailChangeService.class).sendLink(realm.realm(), ada.userId(), inbox, baseUrl() + realm.path());
            context.getBean(RealmMagicLinkSender.class).send(new MagicLinkMessage(realm.realm(), ada.userId(), inbox,
                    baseUrl() + realm.path() + "/login/magic/verify?token=n4me", 15));
            context.getBean(MessagingService.class).sendEmail(realm.realm(), inbox, "otp-email",
                    Map.of("realm", realm.realm(), "code", "271828", "ttl", "5 minutes", "user", "Ada"));
        } finally {
            RealmContextHolder.clear();
        }
        assertNamed(readCapturedEmail(inbox, "/verify-email?token=n4me"), realm, "Verify your email address for Monthfold");
        assertNamed(readCapturedEmail(inbox, "/account/email/verify?token="), realm, "Confirm your new email address");
        assertNamed(readCapturedEmail(inbox, "/login/magic/verify?token=n4me"), realm, "Sign in to Monthfold");
        assertNamed(readCapturedEmail(inbox, "271828"), realm, "Your Monthfold verification code");
    }

    private static void assertNamed(final MailSink.CapturedEmail mail, final ReferenceSetup.Realm realm,
                                    final String subject) {
        assertThat(mail.subject()).isEqualTo(subject);
        String outsideLinks = mail.text();
        for (final String link : mail.links()) {
            outsideLinks = outsideLinks.replace(link, "");
        }
        for (final String part : List.of(mail.subject(), outsideLinks)) {
            assertThat(part).as(subject + ": the realm id outside a link").doesNotContain(realm.realm());
        }
        assertThat(mail.subject() + mail.text()).as(subject).contains("Monthfold");
    }
}
