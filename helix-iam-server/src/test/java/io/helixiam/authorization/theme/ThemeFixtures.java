/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import java.util.List;
import java.util.Map;

/** Themes shared by the theme tests — the Monthfold reference consumer from the spec. */
final class ThemeFixtures {

    private ThemeFixtures() {
    }

    static ThemeColor c(final String light, final String dark) {
        return new ThemeColor(light, dark);
    }

    /** The spec's Monthfold tokens (light + dark), fonts, radius 6, split, English only. */
    static Theme monthfold() {
        final ThemeColors colors = new ThemeColors(c("#1f4d47", "#7fb8ac"), c("#173b36", "#9ccbc0"),
                c("#e3eeeb", "#1a2e2b"), c("#f7f8f6", "#111615"), c("#ffffff", "#192120"), c("#eef1ee", "#0c100f"),
                c("#16211f", "#e8eeec"), c("#56635f", "#a3b0ac"), null, c("#b3401b", "#f0936b"), null,
                c("#1b5e8c", "#7db8e8"), null, null);
        return new Theme(colors, new ThemeTypography("Public Sans", "Source Serif 4", 16), new ThemeShape(6, "comfortable"),
                new ThemeAssets("/realms/firm/theme/assets/logo01.svg", null, "https://cdn.monthfold.example/favicon.png", null),
                new ThemeLayout("split", false, List.of("en")),
                new ThemeTexts(new LocalizedText(Map.of("en", "Monthly reports your clients will actually read.")),
                        null, LocalizedText.of(""), null, null, LocalizedList.of(List.of())),
                new ThemeLinks("https://monthfold.example/privacy", "https://monthfold.example/terms", null), null);
    }

    /** A catalog in which the realm "firm" has the two Monthfold fonts and asset logo01.svg uploaded. */
    static ThemeAssetCatalog monthfoldCatalog() {
        return new ThemeAssetCatalog() {
            @Override
            public boolean hasFont(final String realmId, final String fontName) {
                return "firm".equals(realmId) && List.of("Public Sans", "Source Serif 4").contains(fontName);
            }

            @Override
            public boolean hasAsset(final String realmId, final String assetId, final String extension) {
                return "firm".equals(realmId) && "logo01".equals(assetId);
            }
        };
    }
}
