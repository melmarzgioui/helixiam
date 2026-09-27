/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

/**
 * Normalises a theme before it is validated and stored: values trimmed, blank URLs and blank custom CSS become null
 * (inherit). Colours keep the case they were given (the 1.0 branding API returns exactly what was saved). Texts are kept as given — an empty text is an explicit "show nothing".
 */
public final class ThemeNormalizer {

    private ThemeNormalizer() {
    }

    public static Theme normalize(final Theme t) {
        if (t == null) {
            return Theme.EMPTY;
        }
        final ThemeColors colors = t.colors() == null ? null : ThemeColors.from(role -> {
            final ThemeColor c = t.colors().role(role);
            if (c == null) {
                return null;
            }
            final String light = colour(c.light());
            final String dark = colour(c.dark());
            return light == null && dark == null ? null : new ThemeColor(light, dark);
        });
        final ThemeTypography ty = t.typography() == null ? null : new ThemeTypography(trim(t.typography().fontSans()),
                trim(t.typography().fontDisplay()), t.typography().baseSize());
        final ThemeShape sh = t.shape() == null ? null : new ThemeShape(t.shape().radius(), trim(t.shape().density()));
        final ThemeAssets as = t.assets() == null ? null : new ThemeAssets(trim(t.assets().logoUrl()),
                trim(t.assets().logoDarkUrl()), trim(t.assets().faviconUrl()), trim(t.assets().brandImageUrl()));
        final ThemeLayout ly = t.layout() == null ? null : new ThemeLayout(trim(t.layout().layout()),
                t.layout().showLanguageSwitcher(), t.layout().supportedLocales());
        final ThemeLinks ln = t.links() == null ? null : new ThemeLinks(trim(t.links().privacyUrl()),
                trim(t.links().termsUrl()), trim(t.links().supportUrl()));
        final String css = t.customCss() == null || t.customCss().isBlank() ? null : t.customCss().strip();
        return new Theme(nullIfEmpty(colors), ty, sh, as, ly, t.texts(), ln, css);
    }

    private static ThemeColors nullIfEmpty(final ThemeColors c) {
        if (c == null) {
            return null;
        }
        for (final String role : ThemeColors.ROLES) {
            if (c.role(role) != null) {
                return c;
            }
        }
        return null;
    }

    private static String colour(final String v) {
        return trim(v);
    }

    private static String trim(final String v) {
        return v == null || v.isBlank() ? null : v.strip();
    }
}
