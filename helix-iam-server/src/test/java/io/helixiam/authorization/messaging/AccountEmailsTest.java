/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging;

import io.helixiam.authorization.i18n.I18nConfig;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.notification.delivery.spi.EmailComposer;
import io.helixiam.notification.domain.NotificationCode;
import io.helixiam.notification.domain.NotificationRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

/** Item A7: the verification (and reset) email — a realm link, the code, the code page; localised and branded. */
class AccountEmailsTest {

    private static final EmailBranding MONTHFOLD = new EmailBranding("Monthfold", "https://cdn.monthfold.example/logo.png",
            "#1f4d47");
    private final AccountEmails emails = new AccountEmails(new I18nConfig().messageSource(), realm -> MONTHFOLD,
            "https://auth.monthfold.example/");

    @AfterEach
    void clear() {
        RealmContextHolder.clear();
        LocaleContextHolder.resetLocaleContext();
    }

    @Test
    void theVerificationEmail_linksToTheRealmsVerifyUrl_showsTheCode_andLinksTheCodePage() {
        final EmailComposer.ComposedEmail mail = emails.compose("USER_SIGNUP", "monthfold", "0b7c-42", Locale.ENGLISH, MONTHFOLD);

        assertThat(mail.html()).isTrue();
        assertThat(mail.subject()).isEqualTo("Confirm your email address for Monthfold");
        assertThat(mail.body())
                .contains("href=\"https://auth.monthfold.example/realms/monthfold/register/verify/0b7c-42\"")
                .contains(">0b7c-42</strong>")
                .contains("href=\"https://auth.monthfold.example/realms/monthfold/register/verify\"")
                .contains("bgcolor=\"#1f4d47\"").contains("src=\"https://cdn.monthfold.example/logo.png\"")
                .contains("<html lang=\"en\">").doesNotContain("HelixIAM");
    }

    @Test
    void inDutch_theWholeEmailIsDutch() {
        final EmailComposer.ComposedEmail mail = emails.compose("USER_SIGNUP", "monthfold", "c0de", Locale.forLanguageTag("nl"),
                MONTHFOLD);
        assertThat(mail.subject()).isEqualTo("Bevestig je e-mailadres voor Monthfold");
        assertThat(mail.body()).contains("<html lang=\"nl\">").contains("E-mailadres bevestigen")
                .contains("Verstuurd door Monthfold.").doesNotContain("Confirm");
    }

    @Test
    void theResetEmail_linksToTheRealmsResetPage() {
        final EmailComposer.ComposedEmail mail = emails.compose("USER_RESET_PASSWORD", "monthfold", "r-1", Locale.ENGLISH,
                MONTHFOLD);
        assertThat(mail.subject()).isEqualTo("Reset your Monthfold password");
        assertThat(mail.body()).contains("href=\"https://auth.monthfold.example/realms/monthfold/reset/password/r-1\"");
    }

    @Test
    void theBrandNameIsEscaped_andAnOddCodeIsEncodedInTheLink() {
        final EmailBranding evil = new EmailBranding("<b>Evil</b> & Co", null, "#123456");
        final EmailComposer.ComposedEmail mail = emails.compose("USER_SIGNUP", "monthfold", "a b\"<x>", Locale.ENGLISH, evil);
        assertThat(mail.body()).doesNotContain("<b>Evil").contains("&lt;b&gt;Evil&lt;/b&gt; &amp; Co")
                .contains("/register/verify/a%20b%22%3Cx%3E\"").doesNotContain("<x>");
    }

    @Test
    void withoutABaseUrl_theEmailCarriesTheCodeOnly() {
        final AccountEmails noBase = new AccountEmails(new I18nConfig().messageSource(), realm -> MONTHFOLD, "");
        final EmailComposer.ComposedEmail mail = noBase.compose("USER_SIGNUP", "monthfold", "c0de", Locale.ENGLISH, MONTHFOLD);
        assertThat(mail.body()).contains(">c0de</strong>").doesNotContain("/register/verify");
    }

    @Test
    void notifications_outsideARealm_orOfAnotherType_useTheFallback() {
        final NotificationRequest signup = new NotificationRequest("USER_SIGNUP");
        signup.setNotificationCode(new NotificationCode("u1", "c0de", "USER_SIGNUP"));
        assertThat(emails.compose(signup)).isEmpty();

        RealmContextHolder.set("monthfold");
        LocaleContextHolder.setLocale(Locale.forLanguageTag("nl"));
        assertThat(emails.compose(signup)).get().extracting(EmailComposer.ComposedEmail::subject)
                .isEqualTo("Bevestig je e-mailadres voor Monthfold");
        assertThat(emails.compose(new NotificationRequest("NEW_REGISTERED_USER"))).isEmpty();
    }

    @Test
    void theTextPart_ofTheVerificationEmail_hasTheLink_theCode_andTheCodePage() {
        final EmailComposer.ComposedEmail mail = emails.compose("USER_SIGNUP", "monthfold", "0b7c-42", Locale.ENGLISH, MONTHFOLD);

        assertThat(mail.text()).isEqualTo("""
                Thanks for creating your Monthfold account. Confirm your email address to finish.

                Confirm email address:
                https://auth.monthfold.example/realms/monthfold/register/verify/0b7c-42

                Or enter this code on the confirmation page:
                0b7c-42
                https://auth.monthfold.example/realms/monthfold/register/verify

                If you did not create this account, you can ignore this email.

                --\s
                Sent by Monthfold.""");
        assertThat(mail.text()).doesNotContain("<").doesNotContain("HTML");
    }

    @Test
    void theTextPart_isDutch_inDutch() {
        final EmailComposer.ComposedEmail mail = emails.compose("USER_SIGNUP", "monthfold", "c0de", Locale.forLanguageTag("nl"),
                MONTHFOLD);
        assertThat(mail.text()).contains("E-mailadres bevestigen:\nhttps://auth.monthfold.example/realms/monthfold/register/verify/c0de")
                .contains("Of vul deze code in op de bevestigingspagina:\nc0de").contains("Verstuurd door Monthfold.")
                .doesNotContain("Confirm");
    }

    @Test
    void theTextPart_ofTheResetEmail_hasTheLinkAndTheCode() {
        final EmailComposer.ComposedEmail mail = emails.compose("USER_RESET_PASSWORD", "monthfold", "r-1", Locale.ENGLISH,
                MONTHFOLD);
        assertThat(mail.text()).contains("Choose a new password:\nhttps://auth.monthfold.example/realms/monthfold/reset/password/r-1")
                .contains("Your reset code:\nr-1");
    }

    @Test
    void withoutABaseUrl_theTextPartCarriesTheCode() {
        final AccountEmails noBase = new AccountEmails(new I18nConfig().messageSource(), realm -> MONTHFOLD, "");
        assertThat(noBase.compose("USER_SIGNUP", "monthfold", "c0de", Locale.ENGLISH, MONTHFOLD).text())
                .contains("Or enter this code on the confirmation page:\nc0de").doesNotContain("http");
    }

    @Test
    void theGlobalSmtpVerifyLinkEmail_isBranded_localised_andHasATextPart() {
        final NotificationRequest verify = new NotificationRequest("VERIFY_EMAIL");
        verify.getAdditionalData().put("realm", "monthfold");
        verify.getAdditionalData().put("link", "https://auth.monthfold.example/realms/monthfold/verify-email?token=t0k");
        verify.getAdditionalData().put("ttlHours", "24");
        LocaleContextHolder.setLocale(Locale.forLanguageTag("nl"));

        final EmailComposer.ComposedEmail mail = emails.compose(verify).orElseThrow();

        assertThat(mail.html()).isTrue();
        assertThat(mail.subject()).isEqualTo("Bevestig je e-mailadres voor Monthfold");
        assertThat(mail.body()).contains("href=\"https://auth.monthfold.example/realms/monthfold/verify-email?token=t0k\"")
                .contains("<html lang=\"nl\">");
        assertThat(mail.text()).contains("https://auth.monthfold.example/realms/monthfold/verify-email?token=t0k")
                .contains("24 uur").doesNotContain("<");
    }
}
