/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.org;

import io.helixiam.authorization.domain.org.Organization;
import io.helixiam.authorization.domain.org.OrganizationMember;
import io.helixiam.authorization.repository.org.OrganizationMemberRepository;
import io.helixiam.authorization.repository.org.OrganizationRepository;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Item E4: which hinted organizations refuse a user. */
class OrganizationMembershipPolicyTest {

    private final OrganizationRepository organizations = mock(OrganizationRepository.class);
    private final OrganizationMemberRepository members = mock(OrganizationMemberRepository.class);
    private final OrganizationMembershipPolicy policy = new OrganizationMembershipPolicy(organizations, members);

    private Organization org(final String realm, final boolean enabled, final boolean requireMembership) {
        final Organization o = new Organization(realm, "harbor", "Harbor", "", enabled);
        o.setRequireMembership(requireMembership);
        when(organizations.findById(o.getOrgId())).thenReturn(Optional.of(o));
        when(organizations.findByTenantIdAndName(realm, "harbor")).thenReturn(Optional.of(o));
        when(members.findByOrgIdAndUserId(any(), any())).thenReturn(Optional.empty());
        return o;
    }

    @Test
    void aNonMember_isRefused_byIdOrName_onlyWhenTheOrganizationRequiresMembership() {
        final Organization o = org("mf", true, true);
        assertThat(policy.deniedOrganization("mf", o.getOrgId(), "u1")).contains(o);
        assertThat(policy.deniedOrganization("mf", " harbor ", "u1")).contains(o);
        o.setRequireMembership(false);
        assertThat(policy.deniedOrganization("mf", o.getOrgId(), "u1")).isEmpty();
    }

    @Test
    void aMember_anotherRealmsOrganization_aDisabledOne_orNoHint_requireNothing() {
        final Organization o = org("mf", true, true);
        when(members.findByOrgIdAndUserId(o.getOrgId(), "member")).thenReturn(Optional.of(new OrganizationMember()));
        assertThat(policy.deniedOrganization("mf", o.getOrgId(), "member")).isEmpty();
        assertThat(policy.deniedOrganization("other", o.getOrgId(), "u1")).isEmpty();
        assertThat(policy.deniedOrganization("mf", null, "u1")).isEmpty();
        o.setEnabled(false);
        assertThat(policy.deniedOrganization("mf", o.getOrgId(), "u1")).isEmpty();
    }
}
