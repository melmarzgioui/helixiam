/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.microsoft.playwright.Locator;
import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Item A7: the registration verification email, sent through the realm's own (HTTP) email provider, carries a
 * clickable link to {@code /realms/{realm}/register/verify/{code}}; a page to type the code exists for those who
 * cannot click; the email is localised and branded. Driven from the RP's sign-in, in a real browser.
 */
class RegistrationVerificationBrowserE2eTest extends AbstractBrowserE2eTest {

    static final String PASSWORD = "Registration-Passw0rd-2026!";
    private static final Pattern VERIFY_LINK = Pattern.compile("https?://[^\"'\\s<>]+/register/verify/([A-Za-z0-9-]+)");

    @Test
    void theVerificationEmail_carriesAClickableRealmLink_throughTheRealmsEmailProvider_andTheLinkVerifies() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final String email = E2eSeed.unique("newcomer") + "@monthfold.test";

        startSignInAtRp(realm.web());
        registerFromTheLoginPage(email);

        final MailSink.CapturedEmail mail = readCapturedEmail(email);
        assertThat(mail.from()).as("sent by the realm's own email provider").isEqualTo("no-reply@monthfold.test");
        assertThat(mail.authorization()).isEqualTo("Bearer mail-sink-token");
        assertThat(mail.html()).isTrue();
        assertThat(mail.subject()).contains("Monthfold").doesNotContain("HelixIAM");
        final String link = verifyLink(mail, realm);
        assertThat(mail.body()).as("a clickable link").contains("href=\"" + link + "\"")
                .as("the code, for the code page").contains(codeOf(link))
                .as("the code page").contains(baseUrl() + realm.path() + "/register/verify\"");

        // Before verification the account cannot sign in.
        page().navigate(baseUrl() + realm.path() + "/login");
        signInWithPassword(email, PASSWORD);
        assertOnIdpPath("/login");

        page().navigate(link);
        assertThat(page().locator("[role=status]").first().innerText()).containsIgnoringCase("verified");
        signInWithPassword(email, PASSWORD);
        assertThat(page().url()).doesNotContain("/login");
    }

    @Test
    void theCodePage_verifiesATypedCode_andRejectsAWrongOne() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final String email = E2eSeed.unique("typist") + "@monthfold.test";
        startSignInAtRp(realm.web());
        registerFromTheLoginPage(email);
        final String code = codeOf(verifyLink(readCapturedEmail(email), realm));

        // The success page points to the code page.
        submit(page().locator("a[href$='/register/verify']"));
        assertOnIdpPath("/register/verify");
        page().locator("#code").fill("not-the-code");
        submit(page().locator("form#verifyForm button[type=submit]"));
        assertOnIdpPath("/register/verify");
        assertThat(page().locator("#code-error").innerText()).isNotBlank();
        assertThat(page().locator("#code").getAttribute("aria-invalid")).isEqualTo("true");

        page().locator("#code").fill(code);
        submit(page().locator("form#verifyForm button[type=submit]"));
        assertThat(page().locator("[role=status]").first().innerText()).containsIgnoringCase("verified");
        signInWithPassword(email, PASSWORD);
        assertThat(page().url()).doesNotContain("/login");
    }

    @Test
    void theEmail_isInTheLanguageTheUserRegisteredIn() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final String email = E2eSeed.unique("nieuw") + "@monthfold.test";
        startSignInAtRp(realm.web());
        page().navigate(baseUrl() + realm.path() + "/register?lang=nl");
        fillAndSubmitRegistration(email);
        final MailSink.CapturedEmail mail = readCapturedEmail(email);
        assertThat(mail.subject()).contains("Bevestig");
        assertThat(mail.body()).contains("lang=\"nl\"").contains("e-mailadres");
    }

    // ------------------------------------------------------------------------------------------------

    /** On the IdP login page: follows "Create account", fills the form and submits it. */
    void registerFromTheLoginPage(final String email) {
        assertOnIdpPath("/login");
        submit(page().locator(".subtext a[href$='/register']"));
        assertOnIdpPath("/register");
        fillAndSubmitRegistration(email);
    }

    void fillAndSubmitRegistration(final String email) {
        page().locator("#username").fill(email);
        final Locator required = page().locator("#loginForm input[required]");
        for (int i = 0; i < required.count(); i++) {
            required.nth(i).fill("Test");
        }
        page().locator("#password").fill(PASSWORD);
        page().locator("#repeatPassword").fill(PASSWORD);
        submit(page().locator("#loginForm button[type=submit]"));
        assertThat(page().locator(".actionSuccess").count()).as(describeBrowser()).isEqualTo(1);
    }

    String verifyLink(final MailSink.CapturedEmail mail, final ReferenceSetup.Realm realm) {
        final Matcher m = VERIFY_LINK.matcher(mail.body().replace("&amp;", "&"));
        assertThat(m.find()).as("a verification link in: " + mail.body()).isTrue();
        final String link = m.group();
        assertThat(URI.create(link).getPath()).startsWith(realm.path() + "/register/verify/");
        assertThat(link).startsWith(baseUrl() + realm.path());
        return link;
    }

    static String codeOf(final String link) {
        return link.substring(link.lastIndexOf('/') + 1);
    }
}
