/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.org;

import io.helixiam.authorization.domain.org.Organization;
import io.helixiam.authorization.repository.org.OrganizationRepository;
import io.helixiam.authorization.theme.LegacyBranding;
import io.helixiam.authorization.theme.Theme;
import io.helixiam.authorization.theme.ThemeAssets;
import io.helixiam.authorization.theme.ThemeColors;
import io.helixiam.authorization.theme.ThemeService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;

/**
 * 1.0 item 7 (branding): an organization's display name, logo and primary colour. Since structured theming the logo
 * and colour are a view onto the organization's theme layer ({@code assets.logoUrl}, {@code colors.primary.light});
 * the display name stays on the organization. Values are validated by the theme rules (https or own-asset logo,
 * {@code #RRGGBB} colour with WCAG AA text contrast); sign-in pages read them for the organization in context.
 */
@Service
public class OrganizationBrandingService {

    /** Theme error paths reported under the branding API's field names. */
    private static final Map<String, String> ERROR_KEYS = Map.of(
            "assets.logoUrl", "logoUrl",
            "colors.primary", "primaryColor",
            "contrast.textOnPrimary", "primaryColor");

    private final OrganizationRepository organizations;
    private final ThemeService themes;

    public OrganizationBrandingService(final OrganizationRepository organizations, final ThemeService themes) {
        this.organizations = organizations;
        this.themes = themes;
    }

    @Transactional(readOnly = true)
    public Optional<Branding> get(final String realmId, final String orgId) {
        return inRealm(realmId, orgId).map(o -> toBranding(o, themes.organizationTheme(realmId, o.getOrgId())
                .orElse(Theme.EMPTY)));
    }

    /**
     * Updates the branding values it is given and keeps everything else of the organization theme (the Task 3 review
     * bug: a {@code null} used to wipe the theme's primary colour). Like the legacy realm-settings fields (Task 1 N1),
     * {@code null} means "unchanged"; an empty string clears the value. Empty when the organization is not in the
     * realm; {@link io.helixiam.authorization.theme.ThemeValidationException} (keys {@code logoUrl}/{@code primaryColor})
     * when a value breaks the theme rules.
     */
    @Transactional
    public Optional<Branding> replace(final String realmId, final String orgId, final Branding branding) {
        final Optional<Organization> org = inRealm(realmId, orgId);
        if (org.isEmpty()) {
            return Optional.empty();
        }
        final Optional<ThemeService.ThemeChange> change = themes.patchOrganizationTheme(realmId, org.get().getOrgId(),
                t -> {
                    final LegacyBranding current = LegacyBranding.of(t);
                    return withBranding(t, given(branding.logoUrl(), current.logoUrl()),
                            given(branding.primaryColor(), current.primaryColor()));
                }, ERROR_KEYS);
        if (change.isEmpty()) {
            return Optional.empty();
        }
        final Organization o = org.get();
        if (branding.displayName() != null) {
            o.setDisplayName(blankToNull(branding.displayName()));
        }
        return Optional.of(toBranding(organizations.save(o), change.get().theme()));
    }

    /** The new value: unchanged for null, cleared for blank, else trimmed. */
    private static String given(final String value, final String current) {
        return value == null ? current : blankToNull(value);
    }

    /** The theme with the logo and the primary colour replaced (an unchanged colour keeps its dark value). */
    static Theme withBranding(final Theme t, final String logo, final String primary) {
        final ThemeColors colors = t.colors() == null ? ThemeColors.from(r -> null) : t.colors();
        final ThemeAssets a = t.assets() == null ? new ThemeAssets(null, null, null, null) : t.assets();
        return t.withColors(ThemeColors.from(role -> "primary".equals(role)
                        ? LegacyBranding.color(colors.primary(), primary) : colors.role(role)))
                .withAssets(new ThemeAssets(logo, a.logoDarkUrl(), a.faviconUrl(), a.brandImageUrl()));
    }

    /**
     * Resolves a sign-in {@code organization} hint — an organization id or name — to an enabled organization of
     * the realm, or empty. Returns its id.
     */
    @Transactional(readOnly = true)
    public Optional<String> resolveHint(final String realmId, final String hint) {
        if (realmId == null || hint == null || hint.isBlank()) {
            return Optional.empty();
        }
        return inRealm(realmId, hint.trim()).or(() -> organizations.findByTenantIdAndName(realmId, hint.trim()))
                .filter(Organization::isEnabled).map(Organization::getOrgId);
    }

    private Optional<Organization> inRealm(final String realmId, final String orgId) {
        if (realmId == null || orgId == null) {
            return Optional.empty();
        }
        return organizations.findById(orgId).filter(o -> realmId.equals(o.getTenantId()));
    }

    private static Branding toBranding(final Organization o, final Theme theme) {
        final LegacyBranding view = LegacyBranding.of(theme);
        return new Branding(o.getDisplayName() != null ? o.getDisplayName() : o.getName(), view.logoUrl(),
                view.primaryColor());
    }

    private static String blankToNull(final String v) {
        return v == null || v.isBlank() ? null : v.trim();
    }

    public record Branding(String displayName, String logoUrl, String primaryColor) {
    }
}
