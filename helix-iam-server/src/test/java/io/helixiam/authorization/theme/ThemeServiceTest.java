/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import io.helixiam.authorization.domain.org.Organization;
import io.helixiam.authorization.domain.theme.OrganizationThemeRecord;
import io.helixiam.authorization.domain.theme.RealmThemeRecord;
import io.helixiam.authorization.repository.org.OrganizationRepository;
import io.helixiam.authorization.repository.theme.OrganizationThemeRepository;
import io.helixiam.authorization.repository.theme.RealmThemeRepository;
import io.helixiam.authorization.service.RealmService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static io.helixiam.authorization.theme.ThemeFixtures.c;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Precedence (spec "Precedence" test), storage round-trip, legacy-field mapping and realm scoping of org themes. */
class ThemeServiceTest {

    private final Map<String, RealmThemeRecord> realmRows = new HashMap<>();
    private final Map<String, OrganizationThemeRecord> orgRows = new HashMap<>();
    private final OrganizationRepository orgs = mock(OrganizationRepository.class);
    private final RealmService realms = mock(RealmService.class);
    private ThemeService service;

    @BeforeEach
    void setUp() {
        final RealmThemeRepository realmRepo = mock(RealmThemeRepository.class);
        when(realmRepo.findById(anyString())).thenAnswer(i -> Optional.ofNullable(realmRows.get(i.<String>getArgument(0))));
        when(realmRepo.save(any())).thenAnswer(i -> {
            final RealmThemeRecord r = i.getArgument(0);
            realmRows.put(r.getRealmId(), r);
            return r;
        });
        final OrganizationThemeRepository orgRepo = mock(OrganizationThemeRepository.class);
        when(orgRepo.findById(anyString())).thenAnswer(i -> Optional.ofNullable(orgRows.get(i.<String>getArgument(0))));
        when(orgRepo.save(any())).thenAnswer(i -> {
            final OrganizationThemeRecord r = i.getArgument(0);
            orgRows.put(r.getOrgId(), r);
            return r;
        });
        when(realms.exists("firm")).thenReturn(true);
        when(orgs.findById("org-1")).thenReturn(Optional.of(org("org-1", "firm")));
        when(orgs.findById("org-x")).thenReturn(Optional.of(org("org-x", "other")));
        final StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("catalog", ThemeFixtures.monthfoldCatalog());
        service = new ThemeService(realmRepo, orgRepo, orgs, realms, beans.getBeanProvider(ThemeAssetCatalog.class),
                beans.getBeanProvider(BaseThemeProvider.class), "https://img.monthfold.example");
    }

    private static Organization org(final String id, final String realm) {
        final Organization o = new Organization();
        o.setOrgId(id);
        o.setTenantId(realm);
        o.setName(id);
        o.setEnabled(true);
        return o;
    }

    @Test
    void organizationThemeOverridesPerField_onlyWhenAnOrganizationIsInContext() {
        service.saveRealmTheme("firm", ThemeFixtures.monthfold());
        service.saveOrganizationTheme("firm", "org-1", new Theme(
                ThemeColors.from(r -> r.equals("primary") ? c("#6d28d9", null) : null), null, null,
                new ThemeAssets("https://cdn.org.example/logo.svg", null, null, null), null, null, null, null));

        final Theme realmOnly = service.effectiveTheme("firm", Optional.empty()).theme();
        final Theme withOrg = service.effectiveTheme("firm", Optional.of("org-1")).theme();

        assertThat(realmOnly.colors().primary().light()).isEqualTo("#1f4d47");
        assertThat(realmOnly.assets().logoUrl()).isEqualTo("/realms/firm/theme/assets/logo01.svg");
        assertThat(withOrg.colors().primary().light()).isEqualTo("#6d28d9");
        assertThat(withOrg.colors().primary().dark()).as("derived, not the realm's dark primary")
                .isNotEqualTo("#7fb8ac").matches("#[0-9a-f]{6}");
        assertThat(withOrg.assets().logoUrl()).isEqualTo("https://cdn.org.example/logo.svg");
        assertThat(withOrg.colors().surface()).as("inherited from the realm").isEqualTo(c("#f7f8f6", "#111615"));
        assertThat(withOrg.typography().fontSans()).isEqualTo("Public Sans");
        assertThat(withOrg.colors().border()).as("default").isEqualTo(ThemeDefaults.THEME.colors().border());
        // Another realm's organization never applies.
        assertThat(service.effectiveTheme("firm", Optional.of("org-x")).theme()).isEqualTo(realmOnly);
        // The version changes with the theme.
        assertThat(service.effectiveTheme("firm", Optional.empty()).version())
                .isNotEqualTo(service.effectiveTheme("firm", Optional.of("org-1")).version());
    }

    @Test
    void baseLayersSitBetweenTheDefaultAndTheRealmTheme() {
        final StaticListableBeanFactory beans = new StaticListableBeanFactory();
        final BaseThemeProvider file = realm -> Optional.of(new Theme(null, null, new ThemeShape(12, "compact"),
                null, null, null, null, null));
        beans.addBean("file", file);
        final ThemeService layered = new ThemeService(mock(RealmThemeRepository.class), mock(OrganizationThemeRepository.class),
                orgs, realms, beans.getBeanProvider(ThemeAssetCatalog.class), beans.getBeanProvider(BaseThemeProvider.class), "");
        assertThat(layered.effectiveTheme("firm", Optional.empty()).theme().shape()).isEqualTo(new ThemeShape(12, "compact"));
    }

    @Test
    void invalidThemes_areRefused_withFieldErrors_andNotStored() {
        assertThatThrownBy(() -> service.saveRealmTheme("firm", Theme.EMPTY.withCustomCss("</style><script>x</script>")))
                .isInstanceOf(ThemeValidationException.class)
                .satisfies(e -> assertThat(((ThemeValidationException) e).fieldErrors()).containsKey("customCss"));
        assertThat(realmRows).isEmpty();
        assertThatThrownBy(() -> service.saveOrganizationTheme("firm", "org-1", Theme.EMPTY.withCustomCss(".a{}")))
                .isInstanceOf(ThemeValidationException.class);
    }

    @Test
    void organizationThemesAreScopedToTheirRealm() {
        assertThat(service.organizationTheme("firm", "org-x")).isEmpty();
        assertThat(service.saveOrganizationTheme("firm", "org-x", Theme.EMPTY)).isEmpty();
        assertThat(service.organizationTheme("firm", "org-1")).contains(Theme.EMPTY);
        assertThat(service.organizationTheme("firm", "missing")).isEmpty();
    }

    @Test
    void savedThemesAreNormalised_andChangesListFieldsNotValues() {
        final ThemeService.ThemeChange change = service.saveRealmTheme("firm", Theme.EMPTY.withColors(
                ThemeColors.from(r -> r.equals("primary") ? c(" #1F4D47 ", null) : null)).withCustomCss("  "));
        assertThat(change.theme().colors().primary().light()).isEqualTo("#1F4D47");
        assertThat(change.theme().customCss()).isNull();
        assertThat(change.changedFields()).containsExactly("colors.primary.light");
    }

    @Test
    void legacyRealmSettingsFields_mapOntoTheTheme() {
        service.applyLegacyBranding("firm", new LegacyBranding("https://cdn.example/logo.svg", "#1f4d47", "#f7f8f6",
                "Welcome back", ".helix-form h1 { letter-spacing: 0 }"));

        final Theme stored = service.realmTheme("firm");
        assertThat(stored.assets().logoUrl()).isEqualTo("https://cdn.example/logo.svg");
        assertThat(stored.colors().primary().light()).isEqualTo("#1f4d47");
        assertThat(stored.colors().surface().light()).isEqualTo("#f7f8f6");
        assertThat(stored.texts().welcomeText().resolve(null)).isEqualTo("Welcome back");
        assertThat(stored.customCss()).isEqualTo(".helix-form h1 { letter-spacing: 0 }");
        assertThat(service.legacyBranding("firm")).isEqualTo(new LegacyBranding("https://cdn.example/logo.svg",
                "#1f4d47", "#f7f8f6", "Welcome back", ".helix-form h1 { letter-spacing: 0 }"));

        // Legacy writes keep the rest of the theme, and report errors under the legacy field names.
        service.saveRealmTheme("firm", ThemeMerger.merge(stored, new Theme(null, null, new ThemeShape(4, null), null, null,
                null, null, null)));
        service.applyLegacyBranding("firm", new LegacyBranding(null, "#1f4d47", "#f7f8f6", "Welcome back", null));
        assertThat(service.realmTheme("firm").shape().radius()).isEqualTo(4);
        assertThat(service.realmTheme("firm").assets().logoUrl()).isNull();
        assertThatThrownBy(() -> service.applyLegacyBranding("firm",
                new LegacyBranding("http://insecure.example/l.png", "#ffe14d", null, null, "@import 'x';")))
                .isInstanceOf(ThemeValidationException.class)
                .satisfies(e -> assertThat(((ThemeValidationException) e).fieldErrors())
                        .containsKeys("logoUrl", "primaryColor", "customCss"));
    }

    @Test
    void storedCustomCssThatNoLongerValidates_isSkippedInTheEffectiveTheme() {
        realmRows.put("firm", new RealmThemeRecord("firm", "{\"customCss\":\"@import 'https://evil.example/x.css';\"}"));
        assertThat(service.effectiveTheme("firm", Optional.empty()).theme().customCss()).isNull();
        assertThat(service.notices(Theme.EMPTY.withCustomCss(".a{}"))).containsExactly(CustomCssValidator.NOTICE);
        assertThat(service.notices(Theme.EMPTY)).isEqualTo(List.of());
    }

    @Test
    void unknownOrganizationIds_neverBecomeCacheKeys_andTheCacheIsBounded() {
        for (int n = 0; n < 50; n++) {
            assertThat(service.effectiveTheme("firm", Optional.of("random-" + n)).theme())
                    .isEqualTo(service.effectiveTheme("firm", Optional.empty()).theme());
        }
        service.effectiveTheme("firm", Optional.of("org-x")); // another realm's organization
        assertThat(service.cacheSize()).as("all fall back to the realm key").isEqualTo(1);

        service.maxCacheEntries(3);
        for (int n = 0; n < 10; n++) {
            service.effectiveTheme("realm-" + n, Optional.empty());
        }
        assertThat(service.cacheSize()).isLessThanOrEqualTo(3);
    }

    @Test
    void cacheInvalidation_waitsForTheCommit() {
        service.effectiveTheme("firm", Optional.empty());
        org.springframework.transaction.support.TransactionSynchronizationManager.initSynchronization();
        try {
            service.saveRealmTheme("firm", new Theme(null, null, new ThemeShape(3, null), null, null, null, null, null));
            assertThat(service.cacheSize()).as("not before the commit").isEqualTo(1);
            org.springframework.transaction.support.TransactionSynchronizationManager.getSynchronizations()
                    .forEach(org.springframework.transaction.support.TransactionSynchronization::afterCommit);
            assertThat(service.cacheSize()).isZero();
        } finally {
            org.springframework.transaction.support.TransactionSynchronizationManager.clearSynchronization();
        }
        assertThat(service.effectiveTheme("firm", Optional.empty()).theme().shape().radius()).isEqualTo(3);
    }

    @Test
    void theEffectiveTheme_separatesImgSrcOriginsFromTheCssUrlAllowlist() {
        service.saveRealmTheme("firm", Theme.EMPTY.withAssets(new ThemeAssets("https://cdn.firm.example/l.svg", null, null,
                null)));
        final EffectiveTheme e = service.effectiveTheme("firm", Optional.empty());
        assertThat(e.imageOrigins()).containsExactlyInAnyOrder("https://img.monthfold.example", "https://cdn.firm.example");
        assertThat(e.cssUrlOrigins()).containsExactly("https://img.monthfold.example");
    }

    @Test
    void storedCssThatFailsTheCurrentRules_isNeverHandedToTheLegacyView() {
        // Review C1 (a): accepted by the old validator, stored before the fix.
        realmRows.put("firm", new RealmThemeRecord("firm",
                "{\"customCss\":\"/* </style><script>alert(1)</script> */\",\"assets\":{\"logoUrl\":\"https://a.example/l.svg\"}}"));
        assertThat(service.legacyBranding("firm").customCss()).isNull();
        assertThat(service.legacyBranding("firm").logoUrl()).isEqualTo("https://a.example/l.svg");
        assertThat(service.storedLegacyBranding("firm").customCss()).as("admin/import view of what is stored").isNotNull();
        assertThat(service.effectiveTheme("firm", Optional.empty()).theme().customCss()).isNull();
    }

    private static final String UNSERVABLE = "{\"customCss\":\"/* hidden */ .a{color:red}\"}";

    @Test
    void aLegacyRoundTripKeepsStoredCssThatIsNotServed() {
        // Re-review N1: the settings view shows customCss=null for CSS that fails the current rules; sending that
        // view back (with or without other branding changes) must not silently delete the stored CSS.
        realmRows.put("firm", new RealmThemeRecord("firm", UNSERVABLE));
        final LegacyBranding view = service.legacyBranding("firm");
        assertThat(view.customCss()).isNull();
        service.applyLegacyBranding("firm", view);
        assertThat(service.realmTheme("firm").customCss()).isEqualTo("/* hidden */ .a{color:red}");
        service.applyLegacyBranding("firm", new LegacyBranding(null, "#1f4d47", null, null, null));
        assertThat(service.realmTheme("firm").colors().primary().light()).isEqualTo("#1f4d47");
        assertThat(service.realmTheme("firm").customCss()).as("still kept").isEqualTo("/* hidden */ .a{color:red}");
        // Replacing it with valid CSS through the legacy field works; clearing it is done through PUT /theme.
        service.applyLegacyBranding("firm", new LegacyBranding(null, "#1f4d47", null, null, ".b{color:blue}"));
        assertThat(service.realmTheme("firm").customCss()).isEqualTo(".b{color:blue}");
    }

    @Test
    void organizationResolutionIsCachedToo() {
        final OrganizationRepository counting = orgs;
        for (int n = 0; n < 5; n++) {
            service.effectiveTheme("firm", Optional.of("org-1"));
            service.effectiveTheme("firm", Optional.of("nope"));
        }
        org.mockito.Mockito.verify(counting, org.mockito.Mockito.times(1)).findById("org-1");
        org.mockito.Mockito.verify(counting, org.mockito.Mockito.times(1)).findById("nope");
        // A write to an organization theme still shows up at once (after commit).
        service.saveOrganizationTheme("firm", "org-1", new Theme(null, null, new ThemeShape(9, null), null, null, null,
                null, null));
        assertThat(service.effectiveTheme("firm", Optional.of("org-1")).theme().shape().radius()).isEqualTo(9);
    }

    @Test
    void storedCssThatIsNotServed_isFlaggedInTheNotices() {
        realmRows.put("firm", new RealmThemeRecord("firm", UNSERVABLE));
        assertThat(service.notices("firm", service.realmTheme("firm")))
                .anySatisfy(n -> assertThat(n).contains("not served").contains("comment"));
        service.saveRealmTheme("firm", Theme.EMPTY.withCustomCss(".a{color:red}"));
        assertThat(service.notices("firm", service.realmTheme("firm"))).containsExactly(CustomCssValidator.NOTICE);
    }
}
