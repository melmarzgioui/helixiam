/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import java.util.List;
import java.util.function.BinaryOperator;
import java.util.function.Function;

/**
 * Field-by-field merge of theme layers (spec §1 precedence). A non-null field of the overlay wins; a null one
 * inherits from the base. A colour whose overlay sets {@code light} replaces the whole colour (its {@code dark} is
 * the overlay's, or derived later), so an organization's primary colour never pairs with the realm's dark primary;
 * an overlay that only sets {@code dark} keeps the base's {@code light}. Lists and localised texts are single
 * values (an empty list is an explicit "none").
 *
 * <p>Layers, bottom to top: {@link ThemeDefaults#THEME}, any {@link BaseThemeProvider} layers (e.g. a file theme),
 * the realm theme, and — only when an organization is in context — the organization theme.
 */
public final class ThemeMerger {

    private ThemeMerger() {
    }

    /** Merges the layers bottom-up (the first is the base). */
    public static Theme merge(final List<Theme> layers) {
        Theme out = Theme.EMPTY;
        for (final Theme layer : layers) {
            out = merge(out, layer);
        }
        return out;
    }

    /** {@code overlay} over {@code base}, field by field. */
    public static Theme merge(final Theme base, final Theme overlay) {
        if (base == null) {
            return overlay == null ? Theme.EMPTY : overlay;
        }
        if (overlay == null) {
            return base;
        }
        return new Theme(
                group(base.colors(), overlay.colors(), ThemeMerger::colors),
                group(base.typography(), overlay.typography(), (b, o) -> new ThemeTypography(
                        pick(b, o, ThemeTypography::fontSans), pick(b, o, ThemeTypography::fontDisplay),
                        pick(b, o, ThemeTypography::baseSize))),
                group(base.shape(), overlay.shape(), (b, o) -> new ThemeShape(
                        pick(b, o, ThemeShape::radius), pick(b, o, ThemeShape::density))),
                group(base.assets(), overlay.assets(), (b, o) -> new ThemeAssets(
                        pick(b, o, ThemeAssets::logoUrl), pick(b, o, ThemeAssets::logoDarkUrl),
                        pick(b, o, ThemeAssets::faviconUrl), pick(b, o, ThemeAssets::brandImageUrl))),
                group(base.layout(), overlay.layout(), (b, o) -> new ThemeLayout(
                        pick(b, o, ThemeLayout::layout), pick(b, o, ThemeLayout::showLanguageSwitcher),
                        pick(b, o, ThemeLayout::supportedLocales))),
                group(base.texts(), overlay.texts(), (b, o) -> new ThemeTexts(
                        pick(b, o, ThemeTexts::brandHeadline), pick(b, o, ThemeTexts::brandSubhead),
                        pick(b, o, ThemeTexts::brandByline), pick(b, o, ThemeTexts::welcomeText),
                        pick(b, o, ThemeTexts::footerText), pick(b, o, ThemeTexts::brandBadges))),
                group(base.links(), overlay.links(), (b, o) -> new ThemeLinks(
                        pick(b, o, ThemeLinks::privacyUrl), pick(b, o, ThemeLinks::termsUrl),
                        pick(b, o, ThemeLinks::supportUrl))),
                overlay.customCss() != null ? overlay.customCss() : base.customCss());
    }

    private static ThemeColors colors(final ThemeColors b, final ThemeColors o) {
        return ThemeColors.from(role -> color(b.role(role), o.role(role)));
    }

    /** Merges one colour (see the class comment). */
    static ThemeColor color(final ThemeColor base, final ThemeColor overlay) {
        if (overlay == null || (overlay.light() == null && overlay.dark() == null)) {
            return base;
        }
        if (overlay.light() != null) {
            return overlay;
        }
        return new ThemeColor(base == null ? null : base.light(), overlay.dark());
    }

    private static <G> G group(final G base, final G overlay, final BinaryOperator<G> merge) {
        if (overlay == null) {
            return base;
        }
        if (base == null) {
            return overlay;
        }
        return merge.apply(base, overlay);
    }

    private static <G, V> V pick(final G base, final G overlay, final Function<G, V> field) {
        final V o = field.apply(overlay);
        return o != null ? o : field.apply(base);
    }
}
