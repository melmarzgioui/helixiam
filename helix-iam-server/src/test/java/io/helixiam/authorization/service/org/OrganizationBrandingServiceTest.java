/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.org;

import io.helixiam.authorization.domain.org.Organization;
import io.helixiam.authorization.repository.org.OrganizationRepository;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** 1.0 item 7: the organization hint resolves only to an enabled organization of the same realm. */
class OrganizationBrandingServiceTest {

    private final OrganizationRepository repo = mock(OrganizationRepository.class);
    private final OrganizationBrandingService service = new OrganizationBrandingService(repo);

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
    void brandingFallsBackToTheOrganizationName() {
        when(repo.findById("o-1")).thenReturn(Optional.of(org("o-1", "monthfold", "harbor-pine", true)));
        assertThat(service.get("monthfold", "o-1")).hasValueSatisfying(b -> assertThat(b.displayName()).isEqualTo("harbor-pine"));
        assertThat(service.get("other", "o-1")).isEmpty();
    }
}
