/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.render;

import io.helixiam.authorization.theme.DarkPalette;
import io.helixiam.authorization.theme.Theme;
import io.helixiam.authorization.theme.ThemeColor;
import io.helixiam.authorization.theme.ThemeColors;
import io.helixiam.authorization.theme.ThemeDefaults;
import io.helixiam.authorization.theme.ThemeFixtures;
import io.helixiam.authorization.theme.ThemeMerger;
import io.helixiam.authorization.theme.ThemeShape;
import io.helixiam.authorization.theme.ThemeTypography;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Spec §2: theme.css carries only custom properties (light in :root, dark in a media block), @font-face, custom CSS. */
class ThemeCssRendererTest {

    private static Theme effective(final Theme layer) {
        return DarkPalette.resolve(ThemeMerger.merge(List.of(ThemeDefaults.THEME, layer)));
    }

    private static String lightBlock(final String css) {
        return css.substring(css.indexOf(":root {"), css.indexOf("}", css.indexOf(":root {")));
    }

    private static String darkBlock(final String css) {
        final int media = css.indexOf("@media (prefers-color-scheme: dark)");
        return css.substring(media, css.indexOf("}\n}", media));
    }

    @Test
    void theDefaultThemeRendersEveryContractVariable_lightInRoot_darkInTheMediaBlock() {
        final String css = ThemeCssRenderer.render(effective(Theme.EMPTY), List.of());

        for (final String name : ThemeCssRenderer.COLOR_VARIABLES.values()) {
            assertThat(lightBlock(css)).as(name).contains("--hx-" + name + ": #");
            assertThat(darkBlock(css)).as(name).contains("--hx-" + name + ": #");
        }
        assertThat(lightBlock(css)).contains("--hx-primary: #2f6b52;", "--hx-surface: #f6f1e9;",
                "--hx-on-primary: #ffffff;", "--hx-brand-bg: #22352b;", "--hx-brand-fg: #f6f1e9;",
                "--hx-brand-accent: #a7d8c4;", "--hx-font-size: 16px;", "--hx-radius: 8px;", "--hx-space: 4px;",
                "--hx-font-sans: \"Work Sans\",", "--hx-font-display: \"Work Sans\",", "--hx-font-mono: ",
                "color-scheme: light dark;");
        assertThat(darkBlock(css)).contains("--hx-primary: #a7d8c4;", "--hx-on-primary: #1b2721;",
                "--hx-brand-bg: #0f1612;", "--hx-brand-fg: #eef0ea;");
        assertThat(css).doesNotContain("@font-face").doesNotContain("@import");
        assertThat(ThemeCssRenderer.render(effective(Theme.EMPTY), List.of())).as("deterministic").isEqualTo(css);
    }

    @Test
    void textOnPrimaryIsTheSurfaceRaisedColour_theSamePairTheValidatorChecks() {
        final String css = ThemeCssRenderer.render(effective(ThemeFixtures.monthfold()), List.of());
        assertThat(lightBlock(css)).contains("--hx-primary: #1f4d47;", "--hx-on-primary: #ffffff;");
        assertThat(darkBlock(css)).contains("--hx-primary: #7fb8ac;", "--hx-on-primary: #192120;");
    }

    @Test
    void shapeAndDensity() {
        final String css = ThemeCssRenderer.render(effective(new Theme(null, new ThemeTypography(null, null, 18),
                new ThemeShape(0, "compact"), null, null, null, null, null)), List.of());
        assertThat(lightBlock(css)).contains("--hx-radius: 0px;", "--hx-space: 3px;", "--hx-font-size: 18px;");
    }

    @Test
    void builtInStacks() {
        final String css = ThemeCssRenderer.render(effective(new Theme(null,
                new ThemeTypography("system-serif", "system-mono", null), null, null, null, null, null, null)), List.of());
        assertThat(lightBlock(css)).contains("--hx-font-sans: ui-serif,").contains("--hx-font-display: ui-monospace,");
    }

    @Test
    void uploadedFontsGetFontFaceRules_onlyForTheFamiliesTheThemeNames() {
        final List<FontFace> faces = List.of(
                new FontFace("Public Sans", "/realms/firm/theme/assets/f1.woff2", "100 900", "normal"),
                new FontFace("Public Sans", "/realms/firm/theme/assets/f2.woff2", "400", "italic"),
                new FontFace("Source Serif 4", "/realms/firm/theme/assets/f3.woff2", "600", "normal"),
                new FontFace("Unused Grotesk", "/realms/firm/theme/assets/f4.woff2", "400", "normal"));
        final String css = ThemeCssRenderer.render(effective(ThemeFixtures.monthfold()), faces);

        assertThat(lightBlock(css)).contains("--hx-font-sans: \"Public Sans\", system-ui,")
                .contains("--hx-font-display: \"Source Serif 4\", system-ui,");
        assertThat(css).contains("@font-face {\n  font-family: \"Public Sans\";\n"
                + "  src: url(\"/realms/firm/theme/assets/f1.woff2\") format(\"woff2\");\n"
                + "  font-weight: 100 900;\n  font-style: normal;\n  font-display: swap;\n}");
        assertThat(css).contains("url(\"/realms/firm/theme/assets/f2.woff2\")", "font-style: italic;",
                "url(\"/realms/firm/theme/assets/f3.woff2\")");
        assertThat(css).doesNotContain("Unused Grotesk").doesNotContain("f4.woff2");
    }

    @Test
    void customCssComesLast_afterTheVariablesAndFonts() {
        final Theme layer = ThemeFixtures.monthfold().withCustomCss(".helix-brand { letter-spacing: 0.01em; }");
        final String css = ThemeCssRenderer.render(effective(layer),
                List.of(new FontFace("Public Sans", "/realms/firm/theme/assets/f1.woff2", "400", "normal")));
        assertThat(css).endsWith(".helix-brand { letter-spacing: 0.01em; }\n");
        assertThat(css.indexOf(".helix-brand")).isGreaterThan(css.indexOf("@font-face"))
                .isGreaterThan(css.indexOf("@media (prefers-color-scheme: dark)"));
    }

    @Test
    void valuesThatAreNotValidAreNeverEmitted_evenIfTheyReachTheRenderer() {
        // Defence in depth: stored rows are validated on write; the renderer re-checks every value it prints.
        final Theme bad = new Theme(ThemeColors.from(r -> switch (r) {
            case "primary" -> new ThemeColor("#123456;} body{display:none", "red");
            case "ink" -> new ThemeColor("#000000", "#ffffff");
            default -> null;
        }), new ThemeTypography("Evil\"; } * { x", "a{b}", 99), new ThemeShape(-4, "roomy"), null, null, null, null,
                null);
        final String css = ThemeCssRenderer.render(ThemeMerger.merge(List.of(ThemeDefaults.THEME, bad)),
                List.of(new FontFace("Evil\"; } * { x", "/realms/x/theme/assets/a.woff2\");x(", "400", "normal")));
        assertThat(css).doesNotContain("display:none").doesNotContain("red;").doesNotContain("Evil")
                .doesNotContain("a{b}").doesNotContain("99px").doesNotContain("-4px").doesNotContain("x(");
        assertThat(lightBlock(css)).contains("--hx-primary: #2f6b52;", "--hx-font-size: 16px;", "--hx-radius: 8px;",
                "--hx-space: 4px;", "--hx-font-sans: \"Work Sans\",");
        assertThat(css.chars().filter(ch -> ch == '{').count()).isEqualTo(css.chars().filter(ch -> ch == '}').count());
    }
}
