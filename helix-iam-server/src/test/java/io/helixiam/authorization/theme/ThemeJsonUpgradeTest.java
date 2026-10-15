/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import org.junit.jupiter.api.Test;

import java.util.Locale;

import static io.helixiam.testsupport.Jackson2Fixtures.assertWritesSame;
import static io.helixiam.testsupport.Jackson2Fixtures.read;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Jackson 3 upgrade: {@code realm_theme.theme_json} / {@code organization_theme.theme_json} and theme exports were
 * written by the Jackson 2 line in the canonical form, which is also hashed into the theme's version (ETag). The
 * current code must read them and write, and hash, the same bytes.
 */
class ThemeJsonUpgradeTest {

    @Test
    void aStoredTheme_isReadAndWrittenAndHashedAsBefore() {
        final Theme theme = ThemeFixtures.monthfold().withCustomCss(".hx-card{border-radius:4px}/* Zoë */");
        assertWritesSame("theme-canonical.json", ThemeJson.write(theme));
        assertWritesSame("theme-canonical.sha256", ThemeJson.hash(theme));

        final Theme stored = ThemeJson.read(read("theme-canonical.json"));
        assertThat(stored).isEqualTo(theme);
        assertThat(ThemeJson.hash(stored)).isEqualTo(read("theme-canonical.sha256"));
    }

    @Test
    void aStoredThemeWithTextShorthandsAndUnknownMembers_isRead() {
        final Theme t = ThemeJson.read("{\"futureField\":{\"a\":[1,2]},\"shape\":{\"radius\":4},\"texts\":{"
                + "\"welcomeText\":\"Hi / Zoë\",\"brandHeadline\":{\"en\":\"Hello\",\"nl\":\"Hallo\",\"default\":\"Hey\"},"
                + "\"brandBadges\":[\"SOC 2\",\"ISO 27001\"]}}");
        assertThat(t.shape().radius()).isEqualTo(4);
        assertThat(t.texts().welcomeText().resolve(Locale.GERMAN)).isEqualTo("Hi / Zoë");
        assertWritesSame("theme-shorthands-canonical.json", ThemeJson.write(t));
    }
}
