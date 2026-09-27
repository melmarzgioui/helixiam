/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.asset;

import io.helixiam.authorization.theme.ThemeValidationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Spec §3 upload rules: type by content (magic bytes), size limits per type, strict font names. */
class ThemeAssetRulesTest {

    static final String SVG = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 1 1\"><rect width=\"1\" height=\"1\"/></svg>";

    private static Map<String, String> errors(final Runnable r) {
        try {
            r.run();
        } catch (final ThemeValidationException e) {
            return e.fieldErrors();
        }
        throw new AssertionError("expected a ThemeValidationException");
    }

    @Test
    void aWoff2FontIsAccepted_withDefaults() {
        final ThemeAssetRules.Accepted a = ThemeAssetRules.check("PublicSans.woff2", AssetFixtures.woff2(2048),
                "Public Sans", null, null);
        assertThat(a.kind()).isEqualTo(ThemeAssetKind.FONT);
        assertThat(a.extension()).isEqualTo("woff2");
        assertThat(a.contentType()).isEqualTo("font/woff2");
        assertThat(a.name()).isEqualTo("Public Sans");
        assertThat(a.weight()).isEqualTo("400");
        assertThat(a.style()).isEqualTo("normal");
    }

    @Test
    void fontWeightsAndStyles_areValidated() {
        assertThat(ThemeAssetRules.check("a.woff2", AssetFixtures.woff2(100), "Source Serif 4", "700", "italic").weight())
                .isEqualTo("700");
        assertThat(ThemeAssetRules.check("a.woff2", AssetFixtures.woff2(100), "Source Serif 4", "200 900", null).weight())
                .as("a variable font's range").isEqualTo("200 900");
        assertThat(errors(() -> ThemeAssetRules.check("a.woff2", AssetFixtures.woff2(100), "X", "bold", null)))
                .containsKey("weight");
        assertThat(errors(() -> ThemeAssetRules.check("a.woff2", AssetFixtures.woff2(100), "X", "900 100", null)))
                .containsKey("weight");
        assertThat(errors(() -> ThemeAssetRules.check("a.woff2", AssetFixtures.woff2(100), "X", null, "oblique 10deg")))
                .containsKey("style");
        assertThat(errors(() -> ThemeAssetRules.check("a.png", AssetFixtures.png(), null, "700", null)))
                .as("only fonts have a weight").containsKey("weight");
    }

    @Test
    void imagesAreAccepted_byContent() {
        assertThat(ThemeAssetRules.check("logo.PNG", AssetFixtures.png(), null, null, null).contentType())
                .isEqualTo("image/png");
        assertThat(ThemeAssetRules.check("logo.webp", AssetFixtures.webp(), null, null, null).contentType())
                .isEqualTo("image/webp");
        final ThemeAssetRules.Accepted svg = ThemeAssetRules.check("logo.svg", SVG.getBytes(StandardCharsets.UTF_8),
                null, null, null);
        assertThat(svg.contentType()).isEqualTo("image/svg+xml");
        assertThat(svg.kind()).isEqualTo(ThemeAssetKind.IMAGE);
        assertThat(svg.name()).as("an image's name defaults to its file name").isEqualTo("logo");
        assertThat(ThemeAssetRules.check("my logo (final)!.png", AssetFixtures.png(), null, null, null).name())
                .isEqualTo("my logo -final--");
    }

    @Test
    void theWrongMagicWithAGoodExtension_isRejected() {
        assertThat(errors(() -> ThemeAssetRules.check("font.woff2", AssetFixtures.png(), "X", null, null)).get("file"))
                .contains("woff2");
        assertThat(errors(() -> ThemeAssetRules.check("logo.png", AssetFixtures.woff2(100), null, null, null)).get("file"))
                .contains("PNG");
        assertThat(errors(() -> ThemeAssetRules.check("logo.webp", AssetFixtures.png(), null, null, null)).get("file"))
                .contains("WebP");
        assertThat(errors(() -> ThemeAssetRules.check("logo.png", "<html><script>alert(1)</script>"
                .getBytes(StandardCharsets.UTF_8), null, null, null))).containsKey("file");
        assertThat(errors(() -> ThemeAssetRules.check("logo.svg", AssetFixtures.png(), null, null, null)))
                .containsKey("file");
        assertThat(errors(() -> ThemeAssetRules.check("font.woff2", AssetFixtures.woff1(), "X", null, null)))
                .as("WOFF 1 is not woff2").containsKey("file");
        final byte[] lying = AssetFixtures.woff2(100);
        lying[11] = 1; // header length no longer matches the file
        assertThat(errors(() -> ThemeAssetRules.check("font.woff2", lying, "X", null, null))).containsKey("file");
    }

    @ParameterizedTest
    @ValueSource(strings = {"logo.gif", "logo.jpg", "font.ttf", "font.woff", "font.otf", "logo.html", "logo.svgz",
            "logo", "logo.svg.html", ".png"})
    void otherTypesAreRejected(final String filename) {
        assertThat(errors(() -> ThemeAssetRules.check(filename, AssetFixtures.png(), "X", null, null)))
                .containsKey("file");
    }

    @Test
    void sizeLimits() {
        assertThat(ThemeAssetRules.check("f.woff2", AssetFixtures.woff2(500 * 1024), "X", null, null)).isNotNull();
        assertThat(errors(() -> ThemeAssetRules.check("f.woff2", AssetFixtures.woff2(500 * 1024 + 1), "X", null, null))
                .get("file")).contains("500 KB");
        assertThat(ThemeAssetRules.check("a.png", AssetFixtures.padded(AssetFixtures.png(), 512 * 1024), null, null, null))
                .isNotNull();
        assertThat(errors(() -> ThemeAssetRules.check("a.png", AssetFixtures.padded(AssetFixtures.png(), 512 * 1024 + 1),
                null, null, null)).get("file")).contains("512 KB");
        assertThat(errors(() -> ThemeAssetRules.check("a.webp", AssetFixtures.padded(AssetFixtures.webp(), 512 * 1024 + 1),
                null, null, null)).get("file")).contains("512 KB");
        final String bigSvg = SVG.replace("</svg>", "<desc>" + "x".repeat(256 * 1024) + "</desc></svg>");
        assertThat(errors(() -> ThemeAssetRules.check("a.svg", bigSvg.getBytes(StandardCharsets.UTF_8), null, null, null))
                .get("file")).contains("256 KB");
        assertThat(errors(() -> ThemeAssetRules.check("a.png", new byte[0], null, null, null))).containsKey("file");
    }

    @Test
    void aMaliciousSvgIsRejected_withTheReason() {
        assertThat(errors(() -> ThemeAssetRules.check("a.svg", SVG.replace("<rect", "<script>alert(1)</script><rect")
                .getBytes(StandardCharsets.UTF_8), null, null, null)).get("file")).contains("script");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " Public Sans", "Public Sans ", "Public\"Sans", "Pub;lic", "a}b", "a{b", "a/b", "a\\b",
            "a<b", "a'b", "Public\nSans", "a b", "Ünïcode", "system-sans", "SYSTEM-SERIF", "system-mono",
            "-leading-dash", "sixty-five-characters-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"})
    void fontNamesAreStrict(final String name) {
        assertThat(errors(() -> ThemeAssetRules.check("f.woff2", AssetFixtures.woff2(64), name, null, null)))
                .as("'%s'", name).containsKey("name");
    }

    @Test
    void aFontNeedsAName_andGoodNamesPass() {
        assertThat(errors(() -> ThemeAssetRules.check("f.woff2", AssetFixtures.woff2(64), null, null, null)))
                .containsKey("name");
        for (final String ok : new String[] {"Public Sans", "Source Serif 4", "Inter_Display-v2.1", "a"}) {
            assertThat(ThemeAssetRules.check("f.woff2", AssetFixtures.woff2(64), ok, null, null).name()).isEqualTo(ok);
        }
        assertThat(errors(() -> ThemeAssetRules.check("a.svg", SVG.getBytes(StandardCharsets.UTF_8), "a\"b", null, null)))
                .as("an image name follows the same rule").containsKey("name");
    }
}
