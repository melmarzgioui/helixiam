/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Security: variables are HTML-escaped in HTML templates, so user-controlled values cannot inject markup. */
class TemplateRendererHtmlTest {

    @Test
    void htmlRenderingEscapesValuesButKeepsTheTemplateMarkup() {
        final String out = TemplateRenderer.renderHtml("<p>Hi {{user}}, <a href=\"{{link}}\">go</a></p>",
                Map.of("user", "<a href=\"https://evil.example\">click</a>", "link", "https://idp.example/v?a=1&b=2"));

        assertThat(out).startsWith("<p>Hi &lt;a href=&quot;https://evil.example&quot;&gt;click&lt;/a&gt;, ");
        assertThat(out).contains("<a href=\"https://idp.example/v?a=1&amp;b=2\">go</a>");
    }

    @Test
    void plainRenderingIsUnchanged() {
        assertThat(TemplateRenderer.render("Code {{code}} <x>", Map.of("code", "<1>"))).isEqualTo("Code <1> <x>");
    }
}
