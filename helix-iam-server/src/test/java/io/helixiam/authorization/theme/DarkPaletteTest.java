/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import org.junit.jupiter.api.Test;

import static io.helixiam.authorization.theme.ThemeFixtures.c;
import static org.assertj.core.api.Assertions.assertThat;

/** Spec §1: dark variants are optional; HelixIAM derives them from the light values. */
class DarkPaletteTest {

    @Test
    void missingDarkValues_areDerivedFromLight_andExplicitOnesKept() {
        final Theme light = ThemeMerger.merge(ThemeDefaults.THEME, Theme.EMPTY.withColors(ThemeColors.from(r -> switch (r) {
            case "primary" -> c("#1f4d47", null);
            case "surface" -> c("#f7f8f6", null);
            case "ink" -> c("#16211f", "#e8eeec");
            default -> null;
        })));

        final ThemeColors resolved = DarkPalette.resolve(light).colors();

        assertThat(resolved.ink().dark()).isEqualTo("#e8eeec");
        final String surfaceDark = resolved.surface().dark();
        assertThat(ThemeColorMath.luminance(surfaceDark)).as("a dark surface").isLessThan(0.03);
        final String primaryDark = resolved.primary().dark();
        assertThat(ThemeColorMath.luminance(primaryDark)).as("a light primary for dark mode")
                .isGreaterThan(ThemeColorMath.luminance("#1f4d47"));
        assertThat(ThemeColorMath.contrast(primaryDark, resolved.surfaceRaised().dark())).isGreaterThanOrEqualTo(4.5);
        assertThat(ThemeColorMath.contrast(resolved.ink().dark(), surfaceDark)).isGreaterThanOrEqualTo(4.5);
        for (final String role : ThemeColors.ROLES) {
            assertThat(resolved.role(role).dark()).as(role).matches("#[0-9a-f]{6}");
        }
    }

    @Test
    void derivationKeepsTheHue() {
        final double[] light = ThemeColorMath.toHsl("#1f4d47");
        final double[] dark = ThemeColorMath.toHsl(DarkPalette.derive("primary", "#1f4d47"));
        assertThat(Math.abs(light[0] - dark[0])).isLessThan(4);
    }

    @Test
    void contrastMath() {
        assertThat(ThemeColorMath.contrast("#000000", "#ffffff")).isEqualTo(21.0);
        assertThat(ThemeColorMath.contrast("#777777", "#ffffff")).isBetween(4.47, 4.49);
        assertThat(ThemeColorMath.fromHsl(0, 0, 1)).isEqualTo("#ffffff");
        assertThat(ThemeColorMath.fromHsl(ThemeColorMath.toHsl("#1f4d47")[0], ThemeColorMath.toHsl("#1f4d47")[1],
                ThemeColorMath.toHsl("#1f4d47")[2])).isEqualTo("#1f4d47");
    }
}
