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
}
