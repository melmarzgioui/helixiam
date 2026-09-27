/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.org;

import io.helixiam.authorization.domain.org.Organization;
import io.helixiam.authorization.repository.org.OrganizationRepository;
import io.helixiam.authorization.theme.Theme;
import io.helixiam.authorization.theme.ThemeAssets;
import io.helixiam.authorization.theme.ThemeColor;
import io.helixiam.authorization.theme.ThemeColors;
import io.helixiam.authorization.theme.ThemeService;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;
import java.util.function.UnaryOperator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * 1.0 item 7: the organization hint resolves only to an enabled organization of the same realm, and the branding
 * API is a view onto the organization theme (logo → {@code assets.logoUrl}, colour → {@code colors.primary.light}).
 */
class OrganizationBrandingServiceTest {

    private final OrganizationRepository repo = mock(OrganizationRepository.class);
    private final ThemeService themes = mock(ThemeService.class);
    private final OrganizationBrandingService service = new OrganizationBrandingService(repo, themes);

    private static Organization org(final String id, final String realm, final String name, final boolean enabled) {
        final Organization o = new Organization();
        o.setOrgId(id);
        o.setTenantId(realm);
        o.setName(name);
        o.setEnabled(enabled);
        return o;
    }

    @Test
    void hintResolvesByIdOrName_withinTheRealm_onlyWhenEnabled() {
        when(repo.findById("o-1")).thenReturn(Optional.of(org("o-1", "monthfold", "harbor-pine", true)));
        when(repo.findByTenantIdAndName("monthfold", "harbor-pine")).thenReturn(Optional.of(org("o-1", "monthfold", "harbor-pine", true)));
        when(repo.findById("o-2")).thenReturn(Optional.of(org("o-2", "other", "rival", true)));
        when(repo.findByTenantIdAndName("monthfold", "closed")).thenReturn(Optional.of(org("o-3", "monthfold", "closed", false)));

        assertThat(service.resolveHint("monthfold", "o-1")).contains("o-1");
        assertThat(service.resolveHint("monthfold", "harbor-pine")).contains("o-1");
        assertThat(service.resolveHint("monthfold", "o-2")).as("another realm's organization").isEmpty();
        assertThat(service.resolveHint("monthfold", "closed")).as("disabled").isEmpty();
        assertThat(service.resolveHint("monthfold", " ")).isEmpty();
    }

    @Test
    void brandingFallsBackToTheOrganizationName_andReadsTheOrganizationTheme() {
        when(repo.findById("o-1")).thenReturn(Optional.of(org("o-1", "monthfold", "harbor-pine", true)));
        when(themes.organizationTheme("monthfold", "o-1")).thenReturn(Optional.of(new Theme(
                ThemeColors.from(r -> r.equals("primary") ? ThemeColor.of("#1f6f5c") : null), null, null,
                new ThemeAssets("https://cdn.example/l.svg", null, null, null), null, null, null, null)));

        assertThat(service.get("monthfold", "o-1")).contains(new OrganizationBrandingService.Branding("harbor-pine",
                "https://cdn.example/l.svg", "#1f6f5c"));
        assertThat(service.get("other", "o-1")).isEmpty();
    }

    @Test
    @SuppressWarnings("unchecked")
    void replacingBrandingPatchesTheOrganizationTheme() {
        final Organization o = org("o-1", "monthfold", "harbor-pine", true);
        when(repo.findById("o-1")).thenReturn(Optional.of(o));
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        final Theme[] stored = {Theme.EMPTY.withAssets(new ThemeAssets(null, null, "https://cdn.example/fav.png", null))};
        when(themes.patchOrganizationTheme(eq("monthfold"), eq("o-1"), any(UnaryOperator.class), any(Map.class)))
                .thenAnswer(i -> {
                    stored[0] = ((UnaryOperator<Theme>) i.getArgument(2)).apply(stored[0]);
                    return Optional.of(new ThemeService.ThemeChange(stored[0], java.util.List.of()));
                });
        when(themes.organizationTheme("monthfold", "o-1")).thenAnswer(i -> Optional.of(stored[0]));

        final Optional<OrganizationBrandingService.Branding> out = service.replace("monthfold", "o-1",
                new OrganizationBrandingService.Branding("Harbor & Pine", "https://cdn.example/l.svg", "#1F6F5C"));

        assertThat(out).contains(new OrganizationBrandingService.Branding("Harbor & Pine", "https://cdn.example/l.svg",
                "#1F6F5C"));
        assertThat(o.getDisplayName()).isEqualTo("Harbor & Pine");
        assertThat(stored[0].assets().logoUrl()).isEqualTo("https://cdn.example/l.svg");
        assertThat(stored[0].assets().faviconUrl()).as("the rest of the org theme is kept").isEqualTo("https://cdn.example/fav.png");
        assertThat(stored[0].colors().primary().light()).isEqualToIgnoringCase("#1f6f5c");
    }
}
