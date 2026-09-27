/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import java.util.List;

/**
 * The HelixIAM default theme: the bottom layer of every merge, complete in light and dark. Its colours follow the
 * built-in brand ({@code static/css/brand.css}).
 */
public final class ThemeDefaults {

    /** Built-in font stacks a theme may name. */
    public static final List<String> BUILT_IN_FONTS = List.of("system-sans", "system-serif", "system-mono");

    public static final Theme THEME = new Theme(
            new ThemeColors(
                    new ThemeColor("#476957", "#5eead4"),   // primary
                    new ThemeColor("#365141", "#99f6e4"),   // primaryStrong
                    new ThemeColor("#e6f1ec", "#0f2a2e"),   // primaryTint
                    new ThemeColor("#f6f5f3", "#060a12"),   // surface
                    new ThemeColor("#ffffff", "#0c1424"),   // surfaceRaised
                    new ThemeColor("#f0efea", "#03060c"),   // surfaceSunken
                    new ThemeColor("#22251f", "#eaf1fb"),   // ink
                    new ThemeColor("#5b6560", "#a7b6cc"),   // inkMuted
                    new ThemeColor("#e9e8e3", "#1c2940"),   // border
                    new ThemeColor("#b3261e", "#f2918a"),   // negative
                    new ThemeColor("#fbeaea", "#3a1614"),   // negativeTint
                    new ThemeColor("#2e6b4f", "#34e0b0"),   // positive
                    new ThemeColor("#e6f1ec", "#0e2b24"),   // positiveTint
                    new ThemeColor("#a3d4c4", "#58f0d0")),  // focusRing
            new ThemeTypography("system-sans", "system-sans", 16),
            new ThemeShape(8, "comfortable"),
            new ThemeAssets(null, null, null, null),
            new ThemeLayout("split", true, List.of("en", "nl")),
            new ThemeTexts(null, null, null, null, null, null),
            new ThemeLinks(null, null, null),
            null);

    private ThemeDefaults() {
    }
}
