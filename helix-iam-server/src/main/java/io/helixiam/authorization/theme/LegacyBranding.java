/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

/**
 * The deprecated realm-settings branding fields (B2), kept working for one minor version by mapping them onto the
 * realm theme: {@code logoUrl} → {@code assets.logoUrl}, {@code primaryColor} → {@code colors.primary.light},
 * {@code backgroundColor} → {@code colors.surface.light}, {@code welcomeText} → {@code texts.welcomeText.default},
 * {@code customCss} → {@code customCss}.
 */
public record LegacyBranding(String logoUrl, String primaryColor, String backgroundColor, String welcomeText,
                             String customCss) {

    public static final LegacyBranding NONE = new LegacyBranding(null, null, null, null, null);

    /** Blank values become null (as the old settings API stored them). */
    public LegacyBranding normalized() {
        return new LegacyBranding(blank(logoUrl), blank(primaryColor), blank(backgroundColor), blank(welcomeText),
                blank(customCss));
    }

    /** The legacy view of a stored realm theme layer. */
    public static LegacyBranding of(final Theme t) {
        if (t == null) {
            return NONE;
        }
        return new LegacyBranding(t.assets() == null ? null : t.assets().logoUrl(),
                t.colors() == null || t.colors().primary() == null ? null : t.colors().primary().light(),
                t.colors() == null || t.colors().surface() == null ? null : t.colors().surface().light(),
                t.texts() == null || t.texts().welcomeText() == null ? null
                        : t.texts().welcomeText().values().get(LocalizedText.DEFAULT),
                t.customCss());
    }

    /** {@code t} with these five fields written onto it (null clears a field). */
    public Theme applyTo(final Theme t) {
        final Theme base = t == null ? Theme.EMPTY : t;
        final ThemeColors colors = base.colors() == null ? ThemeColors.from(r -> null) : base.colors();
        final ThemeColors newColors = ThemeColors.from(role -> switch (role) {
            case "primary" -> color(colors.primary(), primaryColor);
            case "surface" -> color(colors.surface(), backgroundColor);
            default -> colors.role(role);
        });
        final ThemeAssets a = base.assets() == null ? new ThemeAssets(null, null, null, null) : base.assets();
        final ThemeTexts x = base.texts() == null ? new ThemeTexts(null, null, null, null, null, null) : base.texts();
        return base.withColors(newColors)
                .withAssets(new ThemeAssets(logoUrl, a.logoDarkUrl(), a.faviconUrl(), a.brandImageUrl()))
                .withTexts(new ThemeTexts(x.brandHeadline(), x.brandSubhead(), x.brandByline(),
                        welcomeText(x.welcomeText()), x.footerText(), x.brandBadges()))
                .withCustomCss(customCss);
    }

    private LocalizedText welcomeText(final LocalizedText current) {
        if (current != null && java.util.Objects.equals(current.values().get(LocalizedText.DEFAULT), welcomeText)) {
            return current; // unchanged: keep any per-locale entries
        }
        return welcomeText == null ? null : LocalizedText.of(welcomeText);
    }

    /**
     * Replaces the light value (null clears the colour); keeps an explicit dark value only while the light value is
     * unchanged, so a new light value gets a derived dark one.
     */
    public static ThemeColor color(final ThemeColor current, final String light) {
        if (light == null) {
            return null;
        }
        if (current != null && light.equalsIgnoreCase(current.light() == null ? "" : current.light())) {
            return current;
        }
        return ThemeColor.of(light);
    }

    private static String blank(final String v) {
        return v == null || v.isBlank() ? null : v.trim();
    }
}
