/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** The shared branded layout every HTML email is wrapped in. */
class EmailLayoutTest {

    private static final String BODY = "<p>Hi Ada,</p><p><a href=\"https://idp.example/x?t=1&amp;u=2\" data-button>Sign in to Monthfold</a></p>";

    @Test
    void wrapsTheBodyInABrandedEmailSafeDocument() {
        final String html = EmailLayout.wrap(new EmailBranding("Harbor & Pine", "https://cdn.example/logo.png", "#B4532A"),
                "Sign in to Monthfold", BODY);

        assertThat(html).startsWith("<!DOCTYPE html>").contains("<title>Sign in to Monthfold</title>");
        assertThat(html).contains("<p>Hi Ada,</p>");
        assertThat(html).contains("<img src=\"https://cdn.example/logo.png\"").contains(">Harbor &amp; Pine<");
        assertThat(html).contains("Harbor &amp; Pine").doesNotContain("Harbor & Pine");
        assertThat(html).as("table layout for Outlook").contains("role=\"presentation\"");
    }

    @Test
    void aDataButtonLinkBecomesASolidButtonInTheBrandColour() {
        final String html = EmailLayout.wrap(new EmailBranding("Monthfold", null, "#B4532A"), "s", BODY);

        assertThat(html).doesNotContain("data-button");
        assertThat(html).contains("bgcolor=\"#B4532A\"");
        assertThat(html).contains("href=\"https://idp.example/x?t=1&amp;u=2\"");
        assertThat(html).containsPattern("<a href=\"https://idp.example/x\\?t=1&amp;u=2\"[^>]*style=\"[^\"]*background-color:#B4532A[^\"]*\"[^>]*>Sign in to Monthfold</a>");
    }

    @Test
    void withoutALogoTheNameIsShown_andUnsafeValuesFallBackToDefaults() {
        final String html = EmailLayout.wrap(new EmailBranding("Monthfold", "javascript:alert(1)", "red; x:y"), "s", BODY);

        assertThat(html).doesNotContain("<img").doesNotContain("javascript:").doesNotContain("red; x:y");
        assertThat(html).contains(">Monthfold<");
        assertThat(html).contains("bgcolor=\"" + EmailBranding.DEFAULT_COLOR + "\"");
    }

    @Test
    void defaultBrandingIsHelixIam() {
        assertThat(EmailBranding.helixIam().name()).isEqualTo("HelixIAM");
        assertThat(EmailLayout.wrap(EmailBranding.helixIam(), "s", "<p>x</p>")).contains(">HelixIAM<");
    }

    @Test
    void theThemePalette_footerText_legalLinks_andLanguage_areUsed() {
        final EmailBranding theme = new EmailBranding("Monthfold", "https://cdn.example/logo.png", "#1f4d47", "#fefefe",
                "#f7f8f6", "#ffffff", "#16211f", "#56635f", "#dcdedc", "© Monthfold BV", "https://m.example/privacy",
                null, "https://m.example/help");
        final String html = EmailLayout.wrap(theme, "s", BODY, java.util.Locale.forLanguageTag("nl"));

        assertThat(html).contains("<html lang=\"nl\">").contains("background-color:#f7f8f6").contains("color:#16211f")
                .contains("border:1px solid #dcdedc").contains("bgcolor=\"#1f4d47\"").contains("color:#fefefe")
                .contains("© Monthfold BV").doesNotContain("Verstuurd door")
                .contains("href=\"https://m.example/privacy\"").contains("href=\"https://m.example/help\"")
                .contains(">Hulp<").doesNotContain("Voorwaarden").doesNotContain("#f6f1e9");
        assertThat(EmailLayout.wrap(EmailBranding.helixIam(), "s", BODY, java.util.Locale.forLanguageTag("nl")))
                .contains("Verstuurd door HelixIAM.");
    }

    @Test
    void unsafeFooterLinksAndColours_fallBack() {
        final EmailBranding bad = new EmailBranding("M", null, "#1f4d47", "white", "url(x)", null, null, null, null,
                "<script>x</script>", "javascript:alert(1)", "http://plain.example", null);
        final String html = EmailLayout.wrap(bad, "s", BODY);
        assertThat(html).doesNotContain("javascript:").doesNotContain("plain.example").doesNotContain("<script>x")
                .contains("&lt;script&gt;x&lt;/script&gt;").doesNotContain("url(x)");
    }

    @Test
    void buttons_areFoundCaseInsensitively_acrossLines_andOtherLinksAreLeftAlone() {
        final String body = "<p><a href=\"https://a.example/1\" data-button>One</a> and "
                + "<A\n HREF=\"https://a.example/2\"\tDATA-BUTTON >Two\nlines</a> "
                + "<a href=\"https://a.example/plain\">plain</a> <a href=\"x\" data-button>no close";
        final String html = EmailLayout.wrap(new EmailBranding("Monthfold", null, "#B4532A"), "s", body);

        assertThat(html).containsPattern("<a href=\"https://a.example/1\"[^>]*background-color:#B4532A[^>]*>One</a>");
        assertThat(html).containsPattern("<a href=\"https://a.example/2\"[^>]*background-color:#B4532A[^>]*>Two\nlines</a>");
        assertThat(html).contains("<a href=\"https://a.example/plain\">plain</a>");
        assertThat(html).as("an unclosed button link stays as written").contains("<a href=\"x\" data-button>no close");
    }

    @Test
    void manyUnclosedButtonLinks_areHandledInLinearTime() {
        // CodeQL #253 (java/polynomial-redos): the lazy "(.*?)</a>" regex rescanned the rest of the body for every
        // unclosed opening tag, quadratic in the body length.
        final String body = "<a href=\"\" data-button>a".repeat(40_000);
        final String html = org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(java.time.Duration.ofSeconds(2),
                () -> EmailLayout.wrap(EmailBranding.helixIam(), "s", body));
        assertThat(html).contains(body);
    }
}
