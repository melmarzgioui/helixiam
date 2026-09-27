/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.render;

import io.helixiam.authorization.theme.Theme;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** The "Save password" button of the password reset page is a plain text button: no key icon. */
class ResetSetPageTest {

    @BeforeAll
    static void thymeleaf() {
        ThemedTemplatesTest.thymeleaf();
    }

    @Test
    void theSavePasswordButton_hasNoIcon() throws Exception {
        final String html = ThemedTemplatesTest.render("reset/set",
                ThemedTemplatesTest.model(ThemedTemplatesTest.page(Theme.EMPTY, null, null)));
        assertThat(html).containsPattern("<button type=\"submit\">\\s*<span>Save password</span>\\s*</button>")
                .doesNotContain("class=\"login\"");
    }
}
