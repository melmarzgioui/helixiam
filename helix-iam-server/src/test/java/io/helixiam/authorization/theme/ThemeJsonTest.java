/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

/** The stored/exported JSON form of a theme: canonical, round-trips, and accepts the text shorthands. */
class ThemeJsonTest {

    @Test
    void roundTrips_andHashesStably() {
        final Theme t = ThemeFixtures.monthfold();
        assertThat(ThemeJson.read(ThemeJson.write(t))).isEqualTo(t);
        assertThat(ThemeJson.hash(t)).isEqualTo(ThemeJson.hash(ThemeJson.read(ThemeJson.write(t)))).hasSize(64);
        assertThat(ThemeJson.hash(t)).isNotEqualTo(ThemeJson.hash(t.withCustomCss(".a{}")));
        assertThat(ThemeJson.write(Theme.EMPTY)).isEqualTo("{}");
        assertThat(Theme.EMPTY.isEmpty()).isTrue();
        assertThat(t.isEmpty()).isFalse();
    }

    @Test
    void textShorthands_andLocaleFallback() {
        final Theme t = ThemeJson.read("{\"texts\":{\"welcomeText\":\"Hi\",\"brandHeadline\":{\"en\":\"Hello\",\"nl\":\"Hallo\","
                + "\"default\":\"Hey\"},\"brandBadges\":[\"SOC 2\"]}}");
        assertThat(t.texts().welcomeText().resolve(Locale.GERMAN)).isEqualTo("Hi");
        assertThat(t.texts().brandHeadline().resolve(Locale.forLanguageTag("nl-BE"))).isEqualTo("Hallo");
        assertThat(t.texts().brandHeadline().resolve(Locale.FRENCH)).isEqualTo("Hey");
        assertThat(t.texts().brandBadges().resolve(Locale.ENGLISH)).isEqualTo(List.of("SOC 2"));
        assertThat(ThemeJson.write(t)).contains("\"welcomeText\":{\"default\":\"Hi\"}");
    }
}
