/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import java.util.List;

/**
 * The HelixIAM default theme: the bottom layer of every merge, complete in light and dark. Its light values are the
 * built-in look of the sign-in pages (cream ground, white cards, sage primary, green-ink text); its dark values are
 * the same palette on a deep green ground. The base stylesheets carry no colours of their own — they read every value
 * from the {@code --hx-*} custom properties that {@code /realms/{realm}/theme.css} renders from this layer (and the
 * realm and organization layers above it).
 */
public final class ThemeDefaults {

    /**
     * Built-in font stacks a theme may name: {@code helix-sans} is the bundled Work Sans (the HelixIAM default),
     * the {@code system-*} stacks use the visitor's own fonts.
     */
    public static final List<String> BUILT_IN_FONTS = List.of("helix-sans", "system-sans", "system-serif", "system-mono");

    public static final Theme THEME = new Theme(
            new ThemeColors(
                    new ThemeColor("#2f6b52", "#a7d8c4"),   // primary — sage
                    new ThemeColor("#285c46", "#c4e6d8"),   // primaryStrong — links, titles, hover
                    new ThemeColor("#e6efe9", "#1f3a2e"),   // primaryTint
                    new ThemeColor("#f6f1e9", "#141d18"),   // surface — page ground (cream)
                    new ThemeColor("#ffffff", "#1b2721"),   // surfaceRaised — cards, fields; text on primary
                    new ThemeColor("#efe8dc", "#0f1612"),   // surfaceSunken
                    new ThemeColor("#22352b", "#eef0ea"),   // ink — green ink
                    new ThemeColor("#5f6b64", "#a9b5ad"),   // inkMuted (AA on surface and raised)
                    new ThemeColor("#e7ded0", "#2c3b33"),   // border
                    new ThemeColor("#9c4b3e", "#f0a58c"),   // negative
                    new ThemeColor("#f6e9e5", "#3a231c"),   // negativeTint
                    new ThemeColor("#2f6b52", "#8fd4b0"),   // positive
                    new ThemeColor("#e6efe9", "#173326"),   // positiveTint
                    new ThemeColor("#2f6b52", "#a7d8c4")),  // focusRing = primary (≥ 3:1)
            new ThemeTypography("helix-sans", "helix-sans", 16),
            new ThemeShape(8, "comfortable"),
            new ThemeAssets(null, null, null, null),
            new ThemeLayout("split", true, List.of("en", "nl")),
            new ThemeTexts(null, null, null, null, null, null),
            new ThemeLinks(null, null, null),
            null);

    private ThemeDefaults() {
    }
}
