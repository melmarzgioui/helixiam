/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import io.helixiam.authorization.theme.render.ThemeCssRenderer;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.helixiam.authorization.theme.ThemeFixtures.c;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * UI/UX review B1: a theme that sets its own palette gets the roles it leaves unset (border, focus ring, tints,
 * sunken surface) derived from ITS colours, never HelixIAM's; the brand panel colours (S8, M1) come from one place.
 */
class ThemePaletteTest {

    private static Theme resolve(final Theme layer) {
        return ThemePalette.resolve(ThemeMerger.merge(List.of(ThemeDefaults.THEME, layer)));
    }

    /** Every hex of the HelixIAM default theme except pure white/black (which any theme may share). */
    private static Set<String> helixHexes() {
        final Set<String> out = new HashSet<>();
        for (final String role : ThemeColors.ROLES) {
            final ThemeColor col = ThemeDefaults.THEME.colors().role(role);
            out.add(col.light().toLowerCase(Locale.ROOT));
            out.add(col.dark().toLowerCase(Locale.ROOT));
        }
        out.remove("#ffffff");
        out.remove("#000000");
        return out;
    }

    @Test
    void aMonthfoldLikeTheme_emitsNoHelixHexInItsStylesheet() {
        final String css = ThemeCssRenderer.render(resolve(ThemeFixtures.monthfold()), List.of());
        final Matcher m = Pattern.compile("#[0-9a-f]{6}").matcher(css);
        final Set<String> leaked = new HashSet<>();
        while (m.find()) {
            if (helixHexes().contains(m.group())) {
                leaked.add(m.group());
            }
        }
        assertThat(leaked).as("HelixIAM colours in a Monthfold theme.css").isEmpty();
    }

    @Test
    void derivedRolesComeFromTheThemesOwnColours() {
        final ThemeColors t = resolve(ThemeFixtures.monthfold()).colors();
        assertThat(t.focusRing()).as("focus ring = primary (≥ 3:1)").isEqualTo(t.primary());
        assertThat(t.border().light()).isEqualTo(ThemeColorMath.mix("#16211f", "#f7f8f6", 0.12));
        assertThat(t.negativeTint().light()).isEqualTo(ThemeColorMath.mix("#b3401b", "#ffffff", 0.12));
        assertThat(t.positiveTint().light()).as("tint of Monthfold's blue positive").isEqualTo(
                ThemeColorMath.mix("#1b5e8c", "#ffffff", 0.12));
        assertThat(t.positiveTint().dark()).isEqualTo(ThemeColorMath.mix("#7db8e8", "#192120", 0.18));
        // Monthfold sets its own primaryTint and surfaceSunken: never replaced.
        assertThat(t.primaryTint()).isEqualTo(c("#e3eeeb", "#1a2e2b"));
        assertThat(t.surfaceSunken()).isEqualTo(c("#eef1ee", "#0c100f"));
    }

    @Test
    void aThemeWithoutItsOwnPalette_keepsTheHelixDefaults_exactly() {
        final Theme logoOnly = new Theme(null, null, null,
                new ThemeAssets("https://cdn.acme.example/logo.svg", null, null, null), null, null, null, null);
        assertThat(resolve(logoOnly).colors()).isEqualTo(ThemeDefaults.THEME.colors());
        assertThat(resolve(Theme.EMPTY).colors()).isEqualTo(ThemeDefaults.THEME.colors());
    }

    @Test
    void anExplicitlySetRole_isNeverDerived() {
        final Theme layer = Theme.EMPTY.withColors(ThemeColors.from(r -> switch (r) {
            case "primary" -> c("#6d28d9", null);
            case "border" -> c("#123456", "#654321");
            default -> null;
        }));
        final ThemeColors t = resolve(layer).colors();
        assertThat(t.border()).isEqualTo(c("#123456", "#654321"));
        assertThat(t.focusRing().light()).isEqualTo("#6d28d9");
    }

    @Test
    void theDefaultFocusRingAndMutedInk_meetWcag() {
        final ThemeColors d = ThemeDefaults.THEME.colors();
        assertThat(ThemeColorMath.contrast(d.focusRing().light(), d.surface().light())).isGreaterThanOrEqualTo(3.0);
        assertThat(ThemeColorMath.contrast(d.focusRing().dark(), d.surface().dark())).isGreaterThanOrEqualTo(3.0);
        assertThat(ThemeColorMath.contrast(d.inkMuted().light(), d.surface().light())).isGreaterThanOrEqualTo(4.5);
        assertThat(ThemeColorMath.contrast(d.inkMuted().light(), d.surfaceRaised().light())).isGreaterThanOrEqualTo(4.5);
    }

    @Test
    void theBrandAccentIsNudgedToAaOnBothPanelGrounds() {
        // A purple primary whose derived dark value is only 3.8:1 on the light panel's ink ground.
        final ThemeColors t = resolve(Theme.EMPTY.withColors(ThemeColors.from(r -> r.equals("primary")
                ? c("#6d28d9", null) : null))).colors();
        assertThat(ThemeColorMath.contrast(t.primary().dark(), t.ink().light())).isLessThan(4.5);
        final BrandPanel.Colors light = BrandPanel.light(t);
        assertThat(ThemeColorMath.contrast(light.accent(), light.background())).isGreaterThanOrEqualTo(4.5);
        final BrandPanel.Colors dark = BrandPanel.dark(t);
        assertThat(ThemeColorMath.contrast(dark.accent(), dark.background())).isGreaterThanOrEqualTo(4.5);
    }

    @Test
    void theDarkBrandPanelStandsApartFromTheFormSide() {
        for (final Theme layer : List.of(Theme.EMPTY, ThemeFixtures.monthfold())) {
            final ThemeColors t = resolve(layer).colors();
            final BrandPanel.Colors dark = BrandPanel.dark(t);
            assertThat(dark.background()).isNotEqualTo(t.surface().dark());
            assertThat(ThemeColorMath.contrast(dark.background(), t.surface().dark())).as("distinct ground")
                    .isGreaterThanOrEqualTo(1.2);
            assertThat(ThemeColorMath.contrast(dark.foreground(), dark.background())).isGreaterThanOrEqualTo(4.5);
            assertThat(ThemeColorMath.contrast(dark.accent(), dark.background())).isGreaterThanOrEqualTo(4.5);
            final BrandPanel.Colors light = BrandPanel.light(t);
            assertThat(light.background()).isEqualTo(t.ink().light());
            assertThat(ThemeColorMath.contrast(light.accent(), light.background())).isGreaterThanOrEqualTo(4.5);
            assertThat(light.foreground()).isEqualTo(t.surface().light());
        }
    }

    // ---- Brand leaks: a theme that sets primary but not primaryStrong/primaryTint gets them from its own primary.

    private static Theme monthfoldWithoutStrongOrTint() {
        final ThemeColors m = ThemeFixtures.monthfold().colors();
        return Theme.EMPTY.withColors(ThemeColors.from(r -> switch (r) {
            case "primaryStrong", "primaryTint" -> null;
            default -> m.role(r);
        }));
    }

    @Test
    void primaryStrongAndTint_areDerivedFromTheThemesPrimary_noHelixHex() {
        final ThemeColors t = resolve(monthfoldWithoutStrongOrTint()).colors();
        final ThemeColor helixStrong = ThemeDefaults.THEME.colors().primaryStrong();
        final ThemeColor helixTint = ThemeDefaults.THEME.colors().primaryTint();
        final String css = ThemeCssRenderer.render(resolve(monthfoldWithoutStrongOrTint()), List.of());
        for (final String hex : List.of(helixStrong.light(), helixStrong.dark(), helixTint.light(), helixTint.dark())) {
            assertThat(css).as(hex).doesNotContain(hex);
        }
        // Hover/pressed: darker than primary in light mode, lighter in dark mode, text on it still AA.
        assertThat(ThemeColorMath.luminance(t.primaryStrong().light())).isLessThan(ThemeColorMath.luminance("#1f4d47"));
        assertThat(ThemeColorMath.luminance(t.primaryStrong().dark())).isGreaterThan(ThemeColorMath.luminance("#7fb8ac"));
        assertThat(ThemeColorMath.contrast(t.surfaceRaised().light(), t.primaryStrong().light())).isGreaterThanOrEqualTo(4.5);
        assertThat(ThemeColorMath.contrast(t.surfaceRaised().dark(), t.primaryStrong().dark())).isGreaterThanOrEqualTo(4.5);
        // As links and titles it sits on the surface: AA there too.
        assertThat(ThemeColorMath.contrast(t.primaryStrong().light(), t.surface().light())).isGreaterThanOrEqualTo(4.5);
        assertThat(ThemeColorMath.contrast(t.primaryStrong().dark(), t.surface().dark())).isGreaterThanOrEqualTo(4.5);
        assertThat(t.primaryTint().light()).isEqualTo(ThemeColorMath.mix("#1f4d47", "#ffffff", 0.12));
    }

    @Test
    void semanticDefaults_stayRedAndGreen_butAreAdjustedToAaOnTheThemesSurface() {
        // A mid-grey surface the HelixIAM red and green do not reach 4.5:1 on.
        final Theme grey = Theme.EMPTY.withColors(ThemeColors.from(r -> switch (r) {
            case "surface" -> c("#bdbdbd", "#3a3a3a");
            case "ink" -> c("#111111", "#ffffff");
            default -> null;
        }));
        final ThemeColors d = ThemeDefaults.THEME.colors();
        assertThat(ThemeColorMath.contrast(d.negative().light(), "#bdbdbd")).isLessThan(4.5);
        final ThemeColors t = resolve(grey).colors();
        for (final String role : List.of("negative", "positive")) {
            final ThemeColor col = t.role(role);
            assertThat(ThemeColorMath.contrast(col.light(), "#bdbdbd")).as(role + " light").isGreaterThanOrEqualTo(4.5);
            assertThat(ThemeColorMath.contrast(col.dark(), "#3a3a3a")).as(role + " dark").isGreaterThanOrEqualTo(4.5);
            // Same hue family as the default (red stays red, green stays green).
            assertThat(Math.abs(ThemeColorMath.toHsl(col.light())[0] - ThemeColorMath.toHsl(d.role(role).light())[0]))
                    .as(role + " hue, degrees").isLessThan(2.0);
        }
        // Where the defaults already pass, they are kept exactly.
        final ThemeColors m = resolve(Theme.EMPTY.withColors(ThemeColors.from(r -> r.equals("primary")
                ? c("#1f4d47", null) : null))).colors();
        assertThat(m.negative()).isEqualTo(d.negative());
        assertThat(m.positive()).isEqualTo(d.positive());
    }
}
