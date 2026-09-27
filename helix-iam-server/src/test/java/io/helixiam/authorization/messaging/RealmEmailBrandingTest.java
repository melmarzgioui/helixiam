/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging;

import io.helixiam.authorization.theme.EffectiveTheme;
import io.helixiam.authorization.theme.LocalizedText;
import io.helixiam.authorization.theme.Theme;
import io.helixiam.authorization.theme.ThemeAssets;
import io.helixiam.authorization.theme.ThemeDefaults;
import io.helixiam.authorization.theme.ThemeFixtures;
import io.helixiam.authorization.theme.ThemeLinks;
import io.helixiam.authorization.theme.ThemeMerger;
import io.helixiam.authorization.theme.ThemePalette;
import io.helixiam.authorization.theme.ThemeTexts;
import io.helixiam.authorization.theme.render.ThemePage;
import io.helixiam.authorization.theme.render.ThemePageResolver;
import io.helixiam.authorization.theme.render.ThemePages;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Structured theming Task 4: an email carries the effective theme of the realm (organization in context on top): logo,
 * light palette, footer text in the user's language and the legal links; the name is the organization's, else the
 * realm's, else HelixIAM.
 */
class RealmEmailBrandingTest {

    private static final String BASE = "https://auth.monthfold.example";

    /** The Monthfold reference theme with a logo, a localised footer and the legal links. */
    private static Theme monthfold(final String logo) {
        final Theme m = ThemeFixtures.monthfold();
        return new Theme(m.colors(), m.typography(), m.shape(), new ThemeAssets(logo, null, null, null), m.layout(),
                new ThemeTexts(null, null, null, null, new LocalizedText(Map.of("en", "© Monthfold BV",
                        "nl", "© Monthfold BV — Utrecht")), null),
                new ThemeLinks("https://monthfold.example/privacy", "https://monthfold.example/terms", null), null);
    }

    private static EmailBranding brand(final Theme layer, final String orgName, final String realmName,
                                       final Locale locale, final String base) {
        final Theme effective = ThemePalette.resolve(ThemeMerger.merge(List.of(ThemeDefaults.THEME, layer)));
        final EffectiveTheme e = new EffectiveTheme(effective, "v1", Set.of(), Set.of());
        final ThemePage page = ThemePages.build(e, "monthfold", orgName == null ? null : "org-1", orgName, realmName,
                locale, "v1");
        return RealmEmailBranding.from(page, e, realmName, base);
    }

    @Test
    void theRealmsThemeGivesTheLogo_palette_footer_andLinks() {
        final EmailBranding b = brand(monthfold("https://cdn.monthfold.example/logo.png"), null, "Monthfold",
                Locale.ENGLISH, BASE);
        assertThat(b.name()).isEqualTo("Monthfold");
        assertThat(b.logoUrl()).isEqualTo("https://cdn.monthfold.example/logo.png");
        assertThat(b.color()).isEqualToIgnoringCase("#1f4d47");
        assertThat(b.onColor()).isEqualToIgnoringCase("#ffffff");
        assertThat(b.background()).isEqualToIgnoringCase("#f7f8f6");
        assertThat(b.ink()).isEqualToIgnoringCase("#16211f");
        assertThat(b.inkMuted()).isEqualToIgnoringCase("#56635f");
        assertThat(b.footerText()).isEqualTo("© Monthfold BV");
        assertThat(b.privacyUrl()).isEqualTo("https://monthfold.example/privacy");
        assertThat(b.termsUrl()).isEqualTo("https://monthfold.example/terms");
        assertThat(b.supportUrl()).isNull();
    }

    @Test
    void theFooterIsInTheUsersLanguage_andTheOrganizationNameWins() {
        final EmailBranding b = brand(monthfold(null), "Harbor & Pine", "Monthfold", Locale.forLanguageTag("nl"), BASE);
        assertThat(b.name()).isEqualTo("Harbor & Pine");
        assertThat(b.footerText()).isEqualTo("© Monthfold BV — Utrecht");
    }

    @Test
    void anUploadedLogo_isMadeAbsoluteOnTheIdpBaseUrl_orLeftOutWithoutOne() {
        final String asset = "/realms/monthfold/theme/assets/abc123.png";
        assertThat(brand(monthfold(asset), null, "Monthfold", Locale.ENGLISH, BASE).logoUrl()).isEqualTo(BASE + asset);
        assertThat(brand(monthfold(asset), null, "Monthfold", Locale.ENGLISH, "").logoUrl()).isNull();
    }

    @Test
    void anUnthemedRealmWithoutADisplayName_isHelixIam() {
        final EmailBranding b = brand(Theme.EMPTY, null, null, Locale.ENGLISH, BASE);
        assertThat(b.name()).isEqualTo("HelixIAM");
        assertThat(b.logoUrl()).isNull();
        assertThat(b.footerText()).isNull();
    }

    @Test
    void noRealm_orAFailingResolver_isHelixIam() {
        final ThemePageResolver resolver = mock(ThemePageResolver.class);
        when(resolver.resolve(eq("mf"), any(), any())).thenThrow(new IllegalStateException("down"));
        final RealmEmailBranding branding = new RealmEmailBranding(resolver, BASE);
        assertThat(branding.brandingFor("mf")).isEqualTo(EmailBranding.helixIam());
        assertThat(branding.brandingFor(null)).isEqualTo(EmailBranding.helixIam());
    }
}
