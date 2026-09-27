/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.org;

import io.helixiam.authorization.domain.org.Organization;
import io.helixiam.authorization.repository.org.OrganizationRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * 1.0 item 7 (branding): an organization's display name, logo and primary colour. The admin API validates the
 * values ({@code OrganizationBrandingController}); sign-in pages read them for the organization in context.
 */
@Service
public class OrganizationBrandingService {

    private final OrganizationRepository organizations;

    public OrganizationBrandingService(final OrganizationRepository organizations) {
        this.organizations = organizations;
    }

    @Transactional(readOnly = true)
    public Optional<Branding> get(final String realmId, final String orgId) {
        return inRealm(realmId, orgId).map(OrganizationBrandingService::toBranding);
    }

    /** Replaces the three branding values (null clears one). Empty when the organization is not in the realm. */
    @Transactional
    public Optional<Branding> replace(final String realmId, final String orgId, final Branding branding) {
        return inRealm(realmId, orgId).map(o -> {
            o.setDisplayName(blankToNull(branding.displayName()));
            o.setLogoUrl(blankToNull(branding.logoUrl()));
            o.setPrimaryColor(blankToNull(branding.primaryColor()));
            return toBranding(organizations.save(o));
        });
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

    private static Branding toBranding(final Organization o) {
        return new Branding(o.getDisplayName() != null ? o.getDisplayName() : o.getName(), o.getLogoUrl(), o.getPrimaryColor());
    }

    private static String blankToNull(final String v) {
        return v == null || v.isBlank() ? null : v.trim();
    }

    public record Branding(String displayName, String logoUrl, String primaryColor) {
    }
}
