/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.render;

import io.helixiam.authorization.theme.Theme;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The maintenance page follows the card-page layout of the other pages (title block with the heading and a
 * description, then the card), in the page's language.
 */
class MaintenancePageTest {

    @BeforeAll
    static void thymeleaf() {
        ThemedTemplatesTest.thymeleaf();
    }

    @Test
    void itIsACardPage_titleThenCard_withTheRetryLinkInTheCard() throws Exception {
        final String html = ThemedTemplatesTest.render("maintenance",
                ThemedTemplatesTest.model(ThemedTemplatesTest.page(Theme.EMPTY, null, null)));
        assertThat(html).containsPattern("<div class=\"container title\">\\s*<h1 class=\"hx-title\">Scheduled maintenance</h1>"
                + "\\s*<div class=\"description\">[^<]+</div>\\s*</div>");
        assertThat(html).containsPattern("<div class=\"container\">\\s*<article>[\\s\\S]*href=\"/realms/acme/login\""
                + "[\\s\\S]*</article>");
        assertThat(html).doesNotContain("actionSuccess").doesNotContain("container center").contains("<html lang=\"en\"");
    }

    @Test
    void itIsLocalised() throws Exception {
        final String html = ThemedTemplatesTest.render("maintenance",
                ThemedTemplatesTest.model(ThemedTemplatesTest.page(Theme.EMPTY, null, null)), java.util.Map.of(),
                Locale.forLanguageTag("nl"));
        assertThat(html).contains("<html lang=\"nl\"").contains("Gepland onderhoud").doesNotContain("Scheduled");
    }
}
