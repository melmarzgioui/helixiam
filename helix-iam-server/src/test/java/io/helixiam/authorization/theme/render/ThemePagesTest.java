/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.render;

import io.helixiam.authorization.theme.DarkPalette;
import io.helixiam.authorization.theme.EffectiveTheme;
import io.helixiam.authorization.theme.LocalizedList;
import io.helixiam.authorization.theme.LocalizedText;
import io.helixiam.authorization.theme.Theme;
import io.helixiam.authorization.theme.ThemeAssets;
import io.helixiam.authorization.theme.ThemeDefaults;
import io.helixiam.authorization.theme.ThemeLayout;
import io.helixiam.authorization.theme.ThemeLinks;
import io.helixiam.authorization.theme.ThemeMerger;
import io.helixiam.authorization.theme.ThemeTexts;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** The page model the shared fragment renders from: texts per locale, safe URLs only, brand name, switcher. */
class ThemePagesTest {

    private static EffectiveTheme effective(final Theme layer) {
        final Theme t = DarkPalette.resolve(ThemeMerger.merge(List.of(ThemeDefaults.THEME, layer)));
        return new EffectiveTheme(t, "v", Set.of(), Set.of());
    }

    private static ThemePage page(final Theme layer, final Locale locale, final String orgName, final String display) {
        return ThemePages.build(effective(layer), "acme", orgName == null ? null : "org-1", orgName, display, locale,
                "0123456789abcdef");
    }

    @Test
    void anUnthemedRealmKeepsTheBuiltInLook() {
        final ThemePage p = page(Theme.EMPTY, Locale.ENGLISH, null, "Acme");
        assertThat(p.branded()).isFalse();
        assertThat(p.brandName()).isEqualTo("HelixIAM");
        assertThat(p.title("Sign in")).isEqualTo("HelixIAM — Sign in");
        assertThat(p.split()).isTrue();
        assertThat(p.brandHeadline()).as("built-in message").isNull();
        assertThat(p.badges()).as("built-in badges").isNull();
        assertThat(p.logoUrl()).isNull();
        assertThat(p.hasFooter()).isFalse();
        assertThat(p.themeColorLight()).isEqualTo("#f6f1e9");
        assertThat(p.themeColorDark()).isEqualTo("#141d18");
        assertThat(p.locales()).extracting(ThemePage.LocaleOption::tag).containsExactly("en", "nl");
        assertThat(p.locales()).extracting(ThemePage.LocaleOption::label).containsExactly("English", "Nederlands");
        assertThat(p.locales()).extracting(ThemePage.LocaleOption::current).containsExactly(true, false);
        assertThat(p.cssVersion()).isEqualTo("0123456789abcdef");
    }

    @Test
    void textsResolvePerLocale_emptyMeansHidden_badgesToo() {
        final Theme layer = new Theme(null, null, null, new ThemeAssets("https://cdn.acme.example/logo.svg", null, null, null),
                new ThemeLayout("centered", true, List.of("en", "de", "nl")),
                new ThemeTexts(new LocalizedText(Map.of("default", "Hello", "de", "Hallo")), LocalizedText.of(""),
                        LocalizedText.of("By Acme"), LocalizedText.of("Welcome back"), LocalizedText.of("© Acme"),
                        LocalizedList.of(List.of())),
                new ThemeLinks("https://acme.example/privacy", null, "https://acme.example/help"), null);

        final ThemePage de = page(layer, Locale.GERMAN, null, "Acme Corp");
        assertThat(de.brandHeadline()).isEqualTo("Hallo");
        assertThat(de.brandSubhead()).isEmpty();
        assertThat(de.badges()).isEmpty();
        assertThat(de.split()).isFalse();
        assertThat(de.branded()).isTrue();
        assertThat(de.brandName()).as("branded realm: its display name").isEqualTo("Acme Corp");
        assertThat(de.hasFooter()).isTrue();
        assertThat(de.locales()).extracting(ThemePage.LocaleOption::label).containsExactly("English", "Deutsch", "Nederlands");
        assertThat(de.locales()).extracting(ThemePage.LocaleOption::current).containsExactly(false, true, false);
        assertThat(page(layer, Locale.FRENCH, null, null).brandHeadline()).isEqualTo("Hello");
        assertThat(page(layer, Locale.FRENCH, null, null).brandName()).as("branded, no display name").isEmpty();
        assertThat(page(layer, Locale.FRENCH, null, null).title("Sign in")).isEqualTo("Sign in");
    }

    @Test
    void theOrganizationNameWins_andOneLocaleOrASwitchedOffSwitcherHidesIt() {
        assertThat(page(Theme.EMPTY, Locale.ENGLISH, "Harbor & Pine", "Acme").brandName()).isEqualTo("Harbor & Pine");
        final Theme one = new Theme(null, null, null, null, new ThemeLayout(null, true, List.of("en")), null, null, null);
        assertThat(page(one, Locale.ENGLISH, null, null).locales()).isEmpty();
        final Theme off = new Theme(null, null, null, null, new ThemeLayout(null, false, List.of("en", "nl")), null, null, null);
        assertThat(page(off, Locale.ENGLISH, null, null).locales()).isEmpty();
    }

    @Test
    void onlyHttpsUrlsOrTheRealmsOwnAssetsSurvive() {
        final Theme evil = new Theme(null, null, null,
                new ThemeAssets("javascript:alert(1)", "https://cdn.acme.example/x\"onerror=\"alert(1)",
                        "/realms/other/theme/assets/a1.png", "data:image/png;base64,AAAA"),
                null, null, new ThemeLinks("javascript:alert(1)", "http://acme.example/terms", "//evil.example"), null);
        final ThemePage p = page(evil, Locale.ENGLISH, null, null);
        assertThat(p.logoUrl()).isNull();
        assertThat(p.logoDarkUrl()).isNull();
        assertThat(p.faviconUrl()).as("another realm's asset").isNull();
        assertThat(p.brandImageUrl()).isNull();
        assertThat(p.privacyUrl()).isNull();
        assertThat(p.termsUrl()).isNull();
        assertThat(p.supportUrl()).isNull();
        assertThat(p.branded()).isFalse();

        final Theme good = new Theme(null, null, null,
                new ThemeAssets("/realms/acme/theme/assets/l1.svg", "https://cdn.acme.example/dark.svg",
                        "/realms/acme/theme/assets/f1.png", "https://cdn.acme.example/hero.webp"),
                null, null, new ThemeLinks("https://acme.example/privacy", "https://acme.example/terms", null), null);
        final ThemePage ok = page(good, Locale.ENGLISH, null, null);
        assertThat(ok.logoUrl()).isEqualTo("/realms/acme/theme/assets/l1.svg");
        assertThat(ok.logoDarkUrl()).isEqualTo("https://cdn.acme.example/dark.svg");
        assertThat(ok.faviconUrl()).isEqualTo("/realms/acme/theme/assets/f1.png");
        assertThat(ok.brandImageUrl()).isEqualTo("https://cdn.acme.example/hero.webp");
        assertThat(ok.termsUrl()).isEqualTo("https://acme.example/terms");
    }
}
