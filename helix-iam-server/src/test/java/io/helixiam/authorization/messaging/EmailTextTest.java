/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Item 3: the plain-text part of an HTML email keeps every link and code, so the email works without HTML. */
class EmailTextTest {

    @Test
    void aButtonBecomesItsLabelAndItsUrl_andTheFallbackLinkStaysAUrl() {
        final String html = "<p>Hi Ada,</p>\n<p>Use the button below to sign in to Monthfold.</p>\n"
                + "<p><a href=\"https://idp.example/realms/mf/login/magic/verify?token=a&amp;b=1\" data-button>Sign in</a></p>\n"
                + "<p style=\"color:#7a7468\">If the button doesn't work, copy this link into your browser:<br>"
                + "<a href=\"https://idp.example/realms/mf/login/magic/verify?token=a&amp;b=1\" style=\"color:#7a7468\">"
                + "https://idp.example/realms/mf/login/magic/verify?token=a&amp;b=1</a></p>";

        assertThat(EmailText.fromHtml(html)).isEqualTo("""
                Hi Ada,

                Use the button below to sign in to Monthfold.

                Sign in: https://idp.example/realms/mf/login/magic/verify?token=a&b=1

                If the button doesn't work, copy this link into your browser:
                https://idp.example/realms/mf/login/magic/verify?token=a&b=1""");
    }

    @Test
    void entitiesAreDecoded_whitespaceCollapsed_andStylesDropped() {
        final String html = "<style>p{color:red}</style><p>Your   code\n is:</p><p style=\"font-size:28px\">"
                + "<strong>123&nbsp;456</strong></p><p>&lt;b&gt;Ada&lt;/b&gt; &amp; Co</p>";

        assertThat(EmailText.fromHtml(html)).isEqualTo("Your code is:\n\n123 456\n\n<b>Ada</b> & Co");
    }

    @Test
    void aScriptLinkIsNotWrittenOut_andUnclosedTagsDoNotBreakIt() {
        assertThat(EmailText.fromHtml("<p><a href=\"javascript:alert(1)\">Click</a></p><p>tail <b")).isEqualTo("Click\n\ntail");
        assertThat(EmailText.fromHtml(null)).isEmpty();
        assertThat(EmailText.fromHtml("<a href=\"https://x.example\">")).isEqualTo("https://x.example");
    }

    @Test
    void aLongBodyOfUnclosedTagsIsLinear() {
        final String html = "<a href=\"x\" ".repeat(50_000);
        final long start = System.nanoTime();
        EmailText.fromHtml(html);
        assertThat(System.nanoTime() - start).isLessThan(2_000_000_000L);
    }
}
