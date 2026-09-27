/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.asset;

import io.helixiam.authorization.theme.Theme;
import io.helixiam.authorization.theme.ThemeAssets;
import io.helixiam.authorization.theme.ThemeService;
import io.helixiam.authorization.theme.ThemeTypography;
import io.helixiam.authorization.theme.ThemeValidationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Per-realm limits, realm scoping, the theme catalog and the delete-when-referenced rule. */
class ThemeAssetServiceTest {

    private static final byte[] SVG = ThemeAssetRulesTest.SVG.getBytes(StandardCharsets.UTF_8);

    private InMemoryStore store;
    private ThemeService themes;
    private ThemeAssetService service;

    @BeforeEach
    void setUp() {
        store = new InMemoryStore();
        themes = mock(ThemeService.class);
        when(themes.realmTheme("a")).thenReturn(Theme.EMPTY);
        when(themes.realmTheme("b")).thenReturn(Theme.EMPTY);
        when(themes.organizationThemes("a")).thenReturn(Map.of());
        when(themes.organizationThemes("b")).thenReturn(Map.of());
        service = new ThemeAssetService(store, themes);
    }

    private ThemeAssetMetadata font(final String realm, final String name, final String weight) {
        return service.upload(realm, "f.woff2", AssetFixtures.woff2(256), name, weight, null);
    }

    private ThemeAssetMetadata image(final String realm) {
        return service.upload(realm, "logo.svg", SVG, null, null, null);
    }

    @Test
    void anUploadIsStoredWithItsMetadata_andInvalidatesTheTheme() {
        final ThemeAssetMetadata m = font("a", "Public Sans", null);
        assertThat(m.id()).matches("[A-Za-z0-9_-]{1,64}");
        assertThat(m.kind()).isEqualTo(ThemeAssetKind.FONT);
        assertThat(m.ext()).isEqualTo("woff2");
        assertThat(m.size()).isEqualTo(256);
        assertThat(m.sha256()).hasSize(64);
        assertThat(m.url()).isEqualTo("/realms/a/theme/assets/" + m.id() + ".woff2");
        assertThat(service.list("a")).extracting(ThemeAssetMetadata::id).containsExactly(m.id());
        assertThat(service.content("a", m.id())).hasValueSatisfying(c -> assertThat(c.bytes()).hasSize(256));
        verify(themes, atLeastOnce()).invalidate("a");
    }

    @Test
    void atMostEightFontsPerRealm() {
        for (int i = 0; i < ThemeAssetRules.MAX_FONTS; i++) {
            font("a", "Font " + i, null);
        }
        assertThatThrownBy(() -> font("a", "Font 9", null)).isInstanceOf(ThemeValidationException.class)
                .satisfies(e -> assertThat(((ThemeValidationException) e).fieldErrors().get("file")).contains("8 fonts"));
        assertThat(font("b", "Font 9", null)).as("the limit is per realm").isNotNull();
        assertThat(image("a")).as("and per kind").isNotNull();
    }

    @Test
    void atMostThirtyTwoImagesPerRealm() {
        for (int i = 0; i < ThemeAssetRules.MAX_IMAGES; i++) {
            image("a");
        }
        assertThatThrownBy(() -> image("a")).isInstanceOf(ThemeValidationException.class)
                .satisfies(e -> assertThat(((ThemeValidationException) e).fieldErrors().get("file")).contains("32 images"));
        assertThat(font("a", "Still OK", null)).isNotNull();
    }

    @Test
    void aFontFaceIsUniquePerRealm_butAFamilyMayHaveSeveralFiles() {
        font("a", "Public Sans", "400");
        font("a", "Public Sans", "700");
        assertThatThrownBy(() -> font("a", "Public Sans", "400")).isInstanceOf(ThemeValidationException.class)
                .satisfies(e -> assertThat(((ThemeValidationException) e).fieldErrors()).containsKey("name"));
        assertThat(font("b", "Public Sans", "400")).isNotNull();
    }

    @Test
    void reviewM3_aFamilyHasOneSpelling_caseInsensitively() {
        font("a", "Public Sans", "400");
        assertThatThrownBy(() -> font("a", "public sans", "700")).isInstanceOf(ThemeValidationException.class)
                .satisfies(e -> assertThat(((ThemeValidationException) e).fieldErrors().get("name"))
                        .contains("Public Sans"));
        assertThatThrownBy(() -> font("a", "PUBLIC SANS", "400")).isInstanceOf(ThemeValidationException.class);
        assertThat(font("a", "Public Sans", "700")).as("the same spelling adds a face").isNotNull();
        assertThat(font("b", "public sans", "400")).as("other realms are independent").isNotNull();
    }

    @Test
    void assetsAreRealmScoped() {
        final ThemeAssetMetadata m = image("a");
        assertThat(service.find("b", m.id())).isEmpty();
        assertThat(service.content("b", m.id())).isEmpty();
        assertThat(service.delete("b", m.id())).isEmpty();
        assertThat(service.find("a", m.id())).isPresent();
    }

    @Test
    void theCatalogAnswersForTheRealmOnly() {
        final ThemeAssetMetadata m = image("a");
        font("a", "Public Sans", null);
        final StoredThemeAssetCatalog catalog = new StoredThemeAssetCatalog(store);
        assertThat(catalog.hasFont("a", "Public Sans")).isTrue();
        assertThat(catalog.hasFont("a", "public sans")).as("exact name").isFalse();
        assertThat(catalog.hasFont("b", "Public Sans")).isFalse();
        assertThat(catalog.hasAsset("a", m.id(), "svg")).isTrue();
        assertThat(catalog.hasAsset("a", m.id(), "png")).as("the extension must match").isFalse();
        assertThat(catalog.hasAsset("b", m.id(), "svg")).isFalse();
    }

    @Test
    void deletingAReferencedAsset_isRefusedNamingEveryReference() {
        final ThemeAssetMetadata logo = image("a");
        final ThemeAssetMetadata font = font("a", "Public Sans", null);
        final String url = logo.url();
        when(themes.realmTheme("a")).thenReturn(new Theme(null, new ThemeTypography(null, "Public Sans", null), null,
                new ThemeAssets(url, null, url, null), null, null, null, ".x { background: url(" + url + ") }"));
        final Map<String, Theme> orgs = new LinkedHashMap<>();
        orgs.put("org-1", Theme.EMPTY.withAssets(new ThemeAssets(null, url, null, null)));
        when(themes.organizationThemes("a")).thenReturn(orgs);

        assertThatThrownBy(() -> service.delete("a", logo.id())).isInstanceOf(ThemeAssetInUseException.class)
                .satisfies(e -> assertThat(((ThemeAssetInUseException) e).references()).containsExactly(
                        "theme.assets.logoUrl", "theme.assets.faviconUrl", "theme.customCss",
                        "organizations.org-1.theme.assets.logoDarkUrl"));
        assertThatThrownBy(() -> service.delete("a", font.id())).isInstanceOf(ThemeAssetInUseException.class)
                .satisfies(e -> assertThat(((ThemeAssetInUseException) e).references())
                        .containsExactly("theme.typography.fontDisplay"));
        assertThat(service.find("a", logo.id())).as("nothing was deleted").isPresent();
        assertThat(service.find("a", font.id())).isPresent();

        // Another file of the same family keeps the reference valid, so one file of it may go.
        final ThemeAssetMetadata bold = font("a", "Public Sans", "700");
        assertThat(service.delete("a", bold.id())).isPresent();
    }

    @Test
    void theDeleteCheckSeesBaseLayers_andFontsTheMountedThemeProvides() {
        final ThemeAssetMetadata logo = image("a");
        final ThemeAssetMetadata font = font("a", "Brand Sans", null);
        // A base layer (any BaseThemeProvider) that uses the uploaded logo and font.
        when(themes.baseLayers("a")).thenReturn(List.of(Theme.EMPTY
                .withAssets(new ThemeAssets(logo.url(), null, null, null))));
        when(themes.realmTheme("a")).thenReturn(new Theme(null,
                new ThemeTypography("Brand Sans", null, null),
                null, null, null, null, null, null));
        assertThatThrownBy(() -> service.delete("a", logo.id())).isInstanceOf(ThemeAssetInUseException.class)
                .satisfies(e -> assertThat(((ThemeAssetInUseException) e).references())
                        .containsExactly("baseTheme.assets.logoUrl"));
        assertThatThrownBy(() -> service.delete("a", font.id())).isInstanceOf(ThemeAssetInUseException.class);

        // The realm's file theme also ships "Brand Sans": the family keeps resolving without the upload.
        service.setMountedThemeAssets(new MountedThemeAssets() {
            @Override
            public Optional<ThemeAssetService.StoredAsset> find(final String realmId, final String assetId) {
                return Optional.empty();
            }

            @Override
            public List<ThemeAssetMetadata> fonts(final String realmId) {
                return List.of(new ThemeAssetMetadata("ft-1", realmId, ThemeAssetKind.FONT, "Brand Sans", "woff2",
                        "font/woff2", 256, "0".repeat(64), "400", "normal", java.time.Instant.now()));
            }
        });
        assertThat(service.delete("a", font.id())).isPresent();
        assertThat(service.servedFonts("a")).extracting(ThemeAssetMetadata::id).containsExactly("ft-1");
    }

    @Test
    void deletingAnUnreferencedAsset_removesIt() {
        final ThemeAssetMetadata m = image("a");
        assertThat(service.delete("a", m.id())).hasValueSatisfying(d -> assertThat(d.id()).isEqualTo(m.id()));
        assertThat(service.find("a", m.id())).isEmpty();
        assertThat(service.delete("a", m.id())).isEmpty();
        verify(themes, atLeastOnce()).invalidate("a");
    }

    /** A map-backed store. */
    static final class InMemoryStore implements ThemeAssetStore {
        private final Map<String, ThemeAssetMetadata> meta = new LinkedHashMap<>();
        private final Map<String, byte[]> bytes = new LinkedHashMap<>();

        @Override
        public void lockRealm(final String realmId) {
            // single-threaded test
        }

        @Override
        public void save(final ThemeAssetMetadata m, final byte[] content) {
            meta.put(m.id(), m);
            bytes.put(m.id(), content);
        }

        @Override
        public List<ThemeAssetMetadata> list(final String realmId) {
            final List<ThemeAssetMetadata> out = new ArrayList<>();
            meta.values().stream().filter(m -> m.realmId().equals(realmId))
                    .sorted(Comparator.comparing(ThemeAssetMetadata::created)).forEach(out::add);
            return out;
        }

        @Override
        public Optional<ThemeAssetMetadata> find(final String realmId, final String assetId) {
            return Optional.ofNullable(meta.get(assetId)).filter(m -> m.realmId().equals(realmId));
        }

        @Override
        public Optional<byte[]> content(final String realmId, final String assetId) {
            return find(realmId, assetId).map(m -> bytes.get(m.id()));
        }

        @Override
        public boolean delete(final String realmId, final String assetId) {
            if (find(realmId, assetId).isEmpty()) {
                return false;
            }
            meta.remove(assetId);
            bytes.remove(assetId);
            return true;
        }

        @Override
        public int count(final String realmId, final ThemeAssetKind kind) {
            return (int) meta.values().stream().filter(m -> m.realmId().equals(realmId) && m.kind() == kind).count();
        }

        @Override
        public boolean hasFont(final String realmId, final String name) {
            return meta.values().stream().anyMatch(m -> m.realmId().equals(realmId) && m.kind() == ThemeAssetKind.FONT
                    && m.name().equals(name));
        }
    }
}
