/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import org.junit.jupiter.api.Test;

import java.util.List;

import static io.helixiam.authorization.theme.ThemeFixtures.c;
import static org.assertj.core.api.Assertions.assertThat;

/** Spec §1 precedence: organization → realm → HelixIAM default, merged field by field. */
class ThemeMergerTest {

    @Test
    void anOverlayWinsPerField_andInheritsTheRest() {
        final Theme realm = ThemeFixtures.monthfold();
        final Theme org = new Theme(ThemeColors.from(r -> r.equals("primary") ? c("#6d28d9", null) : null), null,
                new ThemeShape(null, "compact"), new ThemeAssets("https://cdn.org.example/logo.svg", null, null, null),
                null, null, null, null);

        final Theme merged = ThemeMerger.merge(List.of(ThemeDefaults.THEME, realm, org));

        assertThat(merged.colors().primary()).as("org primary, dark to be derived").isEqualTo(c("#6d28d9", null));
        assertThat(merged.colors().surface()).as("realm surface").isEqualTo(c("#f7f8f6", "#111615"));
        assertThat(merged.colors().border()).as("default border").isEqualTo(ThemeDefaults.THEME.colors().border());
        assertThat(merged.shape().radius()).as("realm radius").isEqualTo(6);
        assertThat(merged.shape().density()).as("org density").isEqualTo("compact");
        assertThat(merged.assets().logoUrl()).isEqualTo("https://cdn.org.example/logo.svg");
        assertThat(merged.assets().faviconUrl()).as("realm favicon").isEqualTo("https://cdn.monthfold.example/favicon.png");
        assertThat(merged.typography().fontSans()).isEqualTo("Public Sans");
        assertThat(merged.texts().brandHeadline().resolve(java.util.Locale.ENGLISH))
                .isEqualTo("Monthly reports your clients will actually read.");
    }

    @Test
    void aDarkOnlyOverlay_keepsTheLightValueBelow() {
        final Theme base = Theme.EMPTY.withColors(ThemeColors.from(r -> r.equals("ink") ? c("#111111", "#eeeeee") : null));
        final Theme over = Theme.EMPTY.withColors(ThemeColors.from(r -> r.equals("ink") ? c(null, "#dddddd") : null));
        assertThat(ThemeMerger.merge(base, over).colors().ink()).isEqualTo(c("#111111", "#dddddd"));
    }

    @Test
    void anEmptyListIsAnExplicitValue_nullInherits() {
        final Theme base = Theme.EMPTY.withTexts(new ThemeTexts(null, null, null, null, null,
                LocalizedList.of(List.of("SOC 2"))));
        final Theme hide = Theme.EMPTY.withTexts(new ThemeTexts(null, null, null, null, null, LocalizedList.of(List.of())));
        assertThat(ThemeMerger.merge(base, hide).texts().brandBadges().resolve(null)).isEmpty();
        assertThat(ThemeMerger.merge(base, Theme.EMPTY).texts().brandBadges().resolve(null)).containsExactly("SOC 2");
    }

    @Test
    void theDefaultTheme_isComplete_inLightAndDark() {
        for (final String role : ThemeColors.ROLES) {
            assertThat(ThemeDefaults.THEME.colors().role(role).light()).as(role).matches("#[0-9a-f]{6}");
            assertThat(ThemeDefaults.THEME.colors().role(role).dark()).as(role).matches("#[0-9a-f]{6}");
        }
        assertThat(new ThemeValidator(ThemeAssetCatalog.NONE, java.util.Set.of())
                .validate("any", ThemeValidator.Scope.REALM, ThemeDefaults.THEME, ThemeDefaults.THEME)).isEmpty();
    }
}
