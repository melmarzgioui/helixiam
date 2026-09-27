/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.file;

import io.helixiam.authorization.theme.Theme;
import io.helixiam.authorization.theme.ThemeUrls;
import io.helixiam.authorization.theme.asset.AssetFixtures;
import io.helixiam.authorization.theme.asset.ThemeAssetKind;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** File themes (spec §5): what a theme directory must contain, and the same rules as the admin API and uploads. */
class FileThemeLoaderTest {

    private static final String LOGO = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 10 10\">"
            + "<rect width=\"10\" height=\"10\" fill=\"#1f4d47\"/></svg>";
    private static final String THEME = """
            {
              "colors": {"primary": {"light": "#1f4d47", "dark": "#7fb8ac"}, "surface": {"light": "#f7f8f6"}},
              "typography": {"fontSans": "Public Sans"},
              "shape": {"radius": 6},
              "assets": {"logoUrl": "assets/logo.svg", "faviconUrl": "https://cdn.monthfold.example/favicon.png"},
              "customCss": ".brand { background-image: url('assets/panel.png'); }"
            }
            """;
    private static final String FONTS = """
            [{"file": "PublicSans.woff2", "family": "Public Sans", "weight": "100 900", "style": "normal"}]
            """;

    @TempDir
    Path root;

    private Path theme(final String name, final String json) throws IOException {
        final Path dir = Files.createDirectories(root.resolve(name));
        if (json != null) {
            Files.writeString(dir.resolve("theme.json"), json);
        }
        return dir;
    }

    private static void asset(final Path dir, final String file, final byte[] bytes) throws IOException {
        Files.createDirectories(dir.resolve("assets"));
        Files.write(dir.resolve("assets").resolve(file), bytes);
    }

    private Path monthfold() throws IOException {
        final Path dir = theme("monthfold", THEME);
        Files.writeString(dir.resolve("fonts.json"), FONTS);
        asset(dir, "logo.svg", LOGO.getBytes(StandardCharsets.UTF_8));
        asset(dir, "panel.png", AssetFixtures.png());
        asset(dir, "PublicSans.woff2", AssetFixtures.woff2(2048));
        return dir;
    }

    private FileThemeLoader.Result load(final String name) {
        return FileThemeLoader.load(root, name, Set.of());
    }

    @Test
    void aValidThemeLoads_withItsAssetsResolvedToTheRealmsAssetPath() throws IOException {
        monthfold();
        final FileThemeLoader.Result r = load("monthfold");
        assertThat(r.problems()).isEmpty();
        assertThat(r.valid()).isTrue();

        final FileTheme t = r.theme();
        assertThat(t.assets()).hasSize(3);
        assertThat(t.fonts()).singleElement().satisfies(f -> {
            assertThat(f.name()).isEqualTo("Public Sans");
            assertThat(f.weight()).isEqualTo("100 900");
            assertThat(f.kind()).isEqualTo(ThemeAssetKind.FONT);
        });
        assertThat(t.assets().keySet()).allMatch(id -> id.matches("ft-[0-9a-f]{40}"));

        final Theme forFirm = t.forRealm("firm");
        final ThemeUrls.AssetRef logo = ThemeUrls.parseAsset(forFirm.assets().logoUrl()).orElseThrow();
        assertThat(logo.realmId()).isEqualTo("firm");
        assertThat(logo.extension()).isEqualTo("svg");
        assertThat(t.asset(logo.assetId())).get().satisfies(a ->
                assertThat(new String(a.bytes(), StandardCharsets.UTF_8)).isEqualTo(LOGO));
        assertThat(forFirm.assets().faviconUrl()).isEqualTo("https://cdn.monthfold.example/favicon.png");
        assertThat(forFirm.customCss()).matches(".*url\\('/realms/firm/theme/assets/ft-[0-9a-f]{40}\\.png'\\).*")
                .doesNotContain(FileTheme.PLACEHOLDER_REALM);
        assertThat(t.forRealm("other").assets().logoUrl()).startsWith("/realms/other/theme/assets/");
    }

    @Test
    void theSameFilesAlwaysGetTheSameIds_andAChangedFileANewOne() throws IOException {
        final Path dir = monthfold();
        final String before = load("monthfold").theme().forRealm("r").assets().logoUrl();
        assertThat(load("monthfold").theme().forRealm("r").assets().logoUrl()).isEqualTo(before);
        Files.writeString(dir.resolve("assets/logo.svg"), LOGO.replace("#1f4d47", "#000000"));
        assertThat(load("monthfold").theme().forRealm("r").assets().logoUrl()).isNotEqualTo(before);
    }

    @Test
    void theThemeJsonIsValidatedLikeTheAdminApi() throws IOException {
        theme("badcolor", "{\"colors\": {\"primary\": {\"light\": \"red\"}}}");
        assertThat(load("badcolor").problems()).containsKey("theme.json: colors.primary.light");

        theme("typo", "{\"colors\": {\"primry\": {\"light\": \"#112233\"}}}");
        assertThat(load("typo").problems()).containsEntry("theme.json: colors.primry", "Unknown field.");

        theme("contrast", "{\"colors\": {\"ink\": {\"light\": \"#eeeeee\"}, \"surface\": {\"light\": \"#ffffff\"}}}");
        assertThat(load("contrast").problems().keySet()).anyMatch(k -> k.startsWith("theme.json: contrast.inkOnSurface"));

        theme("css", "{\"customCss\": \"@import url(https://evil.example/x.css);\"}");
        assertThat(load("css").problems()).containsKey("theme.json: customCss");

        theme("font", "{\"typography\": {\"fontSans\": \"Not Shipped\"}}");
        assertThat(load("font").problems()).containsKey("theme.json: typography.fontSans");

        theme("notjson", "{ nope");
        assertThat(load("notjson").problems()).containsKey("theme.json");

        theme("missing", null);
        assertThat(load("missing").problems()).containsKey("theme.json");
        assertThat(load("missing").valid()).isFalse();
    }

    @Test
    void assetsFollowTheUploadRules() throws IOException {
        final Path svg = theme("evilsvg", "{\"assets\": {\"logoUrl\": \"assets/logo.svg\"}}");
        asset(svg, "logo.svg", "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>"
                .getBytes(StandardCharsets.UTF_8));
        assertThat(load("evilsvg").problems()).containsKey("assets/logo.svg");
        assertThat(load("evilsvg").problems().get("assets/logo.svg")).containsIgnoringCase("script");

        final Path magic = theme("magic", "{}");
        asset(magic, "logo.png", "<html>not a png</html>".getBytes(StandardCharsets.UTF_8));
        assertThat(load("magic").problems()).containsKey("assets/logo.png");

        final Path big = theme("big", "{}");
        asset(big, "huge.png", AssetFixtures.padded(AssetFixtures.png(), 600 * 1024));
        assertThat(load("big").problems()).containsKey("assets/huge.png");

        final Path type = theme("type", "{}");
        asset(type, "script.js", "alert(1)".getBytes(StandardCharsets.UTF_8));
        assertThat(load("type").problems()).containsKey("assets/script.js");

        final Path undeclared = theme("undeclared", "{}");
        asset(undeclared, "Font.woff2", AssetFixtures.woff2(512));
        assertThat(load("undeclared").problems()).containsKey("assets/Font.woff2");

        final Path noFile = theme("nofile", "{\"assets\": {\"logoUrl\": \"assets/nope.svg\"}}");
        Files.createDirectories(noFile.resolve("assets"));
        assertThat(load("nofile").problems()).containsKey("theme.json: assets.logoUrl");

        final Path cssRef = theme("cssref", "{\"customCss\": \".a { background: url(assets/missing.png); }\"}");
        Files.createDirectories(cssRef.resolve("assets"));
        assertThat(load("cssref").problems()).containsKey("theme.json: customCss");

        final Path tooMany = theme("toomany", "{}");
        for (int i = 0; i < 33; i++) {
            asset(tooMany, "img" + i + ".png", AssetFixtures.png());
        }
        assertThat(load("toomany").problems().keySet()).anyMatch(k -> k.startsWith("assets/img"));
    }

    @Test
    void filesOutsideTheThemesDirectoryAreRefused() throws IOException {
        final Path outside = Files.createTempFile("secret", ".svg");
        try {
            Files.writeString(outside, LOGO);
            final Path dir = theme("escape", "{\"assets\": {\"logoUrl\": \"assets/logo.svg\"}}");
            Files.createDirectories(dir.resolve("assets"));
            Files.createSymbolicLink(dir.resolve("assets/logo.svg"), outside);
            assertThat(load("escape").problems()).containsKey("assets/logo.svg");
            assertThat(load("escape").valid()).isFalse();

            final Path traversal = theme("traversal", "{\"assets\": {\"logoUrl\": \"assets/../theme.json\"}}");
            Files.createDirectories(traversal.resolve("assets"));
            assertThat(load("traversal").valid()).isFalse();
        } finally {
            Files.deleteIfExists(outside);
        }
    }

    @Test
    void aKubernetesConfigMapLayoutLoads() throws IOException {
        // kubelet: {root}/..data -> ..2026_09_27/, {root}/monthfold -> ..data/monthfold
        final Path versioned = Files.createDirectories(root.resolve("..2026_09_27"));
        final Path real = Files.createDirectories(versioned.resolve("monthfold"));
        Files.writeString(real.resolve("theme.json"), "{\"assets\": {\"logoUrl\": \"assets/logo.svg\"}}");
        Files.createDirectories(real.resolve("assets"));
        Files.writeString(real.resolve("assets/logo.svg"), LOGO);
        Files.createSymbolicLink(root.resolve("..data"), versioned.getFileName());
        Files.createSymbolicLink(root.resolve("monthfold"), Path.of("..data/monthfold"));

        assertThat(FileThemeLoader.names(root)).containsExactly("monthfold");
        assertThat(load("monthfold").problems()).isEmpty();
    }

    @Test
    void badNamesAreRefused() {
        assertThat(load("../etc").valid()).isFalse();
        assertThat(load("-x").valid()).isFalse();
        assertThat(load("nope").problems()).containsKey("directory");
        assertThat(List.of("monthfold", "Firm.Theme_2", "a")).allMatch(n -> FileThemeLoader.NAME.matcher(n).matches());
    }
}
