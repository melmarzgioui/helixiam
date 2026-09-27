/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.org;

import io.helixiam.authorization.domain.org.Organization;
import io.helixiam.authorization.repository.org.OrganizationMemberRepository;
import io.helixiam.authorization.repository.org.OrganizationRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * Item E4: whether a sign-in with an {@code organization} hint must be refused because the hinted organization
 * requires membership and the user is not a member. The hint is an organization id or name of the realm (like
 * {@link OrganizationBrandingService#resolveHint}); an unknown or disabled organization requires nothing.
 */
@Service
public class OrganizationMembershipPolicy {

    private final OrganizationRepository organizations;
    private final OrganizationMemberRepository members;

    public OrganizationMembershipPolicy(final OrganizationRepository organizations,
                                        final OrganizationMemberRepository members) {
        this.organizations = organizations;
        this.members = members;
    }

    /** The hinted organization that requires membership {@code userId} lacks, if any. */
    @Transactional(readOnly = true)
    public Optional<Organization> deniedOrganization(final String realmId, final String hint, final String userId) {
        if (realmId == null || hint == null || hint.isBlank() || userId == null) {
            return Optional.empty();
        }
        final String h = hint.trim();
        return organizations.findById(h).filter(o -> realmId.equals(o.getTenantId()))
                .or(() -> organizations.findByTenantIdAndName(realmId, h))
                .filter(Organization::isEnabled)
                .filter(Organization::isRequireMembership)
                .filter(o -> members.findByOrgIdAndUserId(o.getOrgId(), userId).isEmpty());
    }
}
