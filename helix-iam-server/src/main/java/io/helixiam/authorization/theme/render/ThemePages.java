/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.render;

import io.helixiam.authorization.theme.EffectiveTheme;
import io.helixiam.authorization.theme.LocalizedList;
import io.helixiam.authorization.theme.LocalizedText;
import io.helixiam.authorization.theme.Theme;
import io.helixiam.authorization.theme.ThemeAssets;
import io.helixiam.authorization.theme.ThemeColorMath;
import io.helixiam.authorization.theme.ThemeLayout;
import io.helixiam.authorization.theme.ThemeLinks;
import io.helixiam.authorization.theme.ThemeTexts;
import io.helixiam.authorization.theme.ThemeUrls;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;

/** Builds the {@link ThemePage} for a page from an effective theme (pure; no request or database access). */
public final class ThemePages {

    /** The product name shown when a realm is not branded (the built-in wordmark is shown too). */
    public static final String DEFAULT_BRAND_NAME = "HelixIAM";

    private ThemePages() {
    }

    /**
     * @param realmId          the realm the page belongs to
     * @param orgId            the organization in context (already checked to belong to the realm), or null
     * @param orgName          its display name, or null
     * @param realmDisplayName the realm's display name, or null
     * @param locale           the page's locale (texts are resolved for it)
     * @param cssVersion       the {@code ?v=} of the realm's theme.css
     */
    public static ThemePage build(final EffectiveTheme effective, final String realmId, final String orgId,
                                  final String orgName, final String realmDisplayName, final Locale locale,
                                  final String cssVersion) {
        final Theme t = effective.theme();
        final ThemeAssets a = t.assets() == null ? new ThemeAssets(null, null, null, null) : t.assets();
        final ThemeLinks l = t.links() == null ? new ThemeLinks(null, null, null) : t.links();
        final ThemeTexts x = t.texts() == null ? new ThemeTexts(null, null, null, null, null, null) : t.texts();
        final Function<String, String> image = url -> image(url, realmId);

        final String logo = image.apply(a.logoUrl());
        final boolean branded = logo != null;
        final String brandName = orgName != null && !orgName.isBlank() ? orgName
                : branded ? (realmDisplayName == null ? "" : realmDisplayName.strip())
                : DEFAULT_BRAND_NAME;
        final String surfaceLight = t.colors() == null || t.colors().surface() == null ? null : t.colors().surface().light();
        final String surfaceDark = t.colors() == null || t.colors().surface() == null ? null : t.colors().surface().dark();

        return new ThemePage(realmId, orgId, orgName, cssVersion, null,
                t.layout() == null || !"centered".equals(t.layout().layout()) ? "split" : "centered",
                branded, brandName,
                logo, branded ? image.apply(a.logoDarkUrl()) : null, image.apply(a.faviconUrl()),
                image.apply(a.brandImageUrl()),
                hex(surfaceLight), hex(surfaceDark),
                text(x.brandHeadline(), locale), text(x.brandSubhead(), locale), text(x.brandByline(), locale),
                text(x.welcomeText(), locale), text(x.footerText(), locale), list(x.brandBadges(), locale),
                link(l.privacyUrl()), link(l.termsUrl()), link(l.supportUrl()),
                locales(t.layout(), locale));
    }

    /** An https URL, or the realm's own uploaded image; anything else is dropped. */
    static String image(final String url, final String realmId) {
        if (url == null) {
            return null;
        }
        if (ThemeUrls.isHttps(url)) {
            return url;
        }
        return ThemeUrls.parseAsset(url)
                .filter(ref -> ref.realmId().equals(realmId) && ThemeUrls.IMAGE_EXTENSIONS.contains(ref.extension()))
                .map(ref -> url)
                .orElse(null);
    }

    private static String link(final String url) {
        return ThemeUrls.isHttps(url) ? url : null;
    }

    private static String hex(final String color) {
        return color != null && ThemeColorMath.isHex(color) ? color.toLowerCase(Locale.ROOT) : null;
    }

    private static String text(final LocalizedText text, final Locale locale) {
        return text == null ? null : text.resolve(locale);
    }

    private static List<String> list(final LocalizedList list, final Locale locale) {
        return list == null ? null : list.resolve(locale);
    }

    private static List<ThemePage.LocaleOption> locales(final ThemeLayout layout, final Locale current) {
        if (layout == null || !Boolean.TRUE.equals(layout.showLanguageSwitcher()) || layout.supportedLocales() == null
                || layout.supportedLocales().size() < 2) {
            return List.of();
        }
        final List<ThemePage.LocaleOption> out = new ArrayList<>();
        for (final String tag : layout.supportedLocales()) {
            final Locale locale = Locale.forLanguageTag(tag);
            final String name = locale.getDisplayName(locale);
            final String label = name.isEmpty() ? tag : name.substring(0, 1).toUpperCase(locale) + name.substring(1);
            final boolean isCurrent = current != null
                    && (tag.equalsIgnoreCase(current.toLanguageTag()) || tag.equalsIgnoreCase(current.getLanguage()));
            out.add(new ThemePage.LocaleOption(tag, label, isCurrent));
        }
        return List.copyOf(out);
    }
}
