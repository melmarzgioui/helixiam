/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging;

import io.helixiam.authorization.amqp.realm.RealmSettingsDto;
import io.helixiam.authorization.security.realm.RealmSettingsResolver;
import io.helixiam.authorization.service.org.OrganizationBrandingService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Email brand: organization in context, else realm, else HelixIAM. */
class RealmEmailBrandingTest {

    private final RealmSettingsResolver realms = mock(RealmSettingsResolver.class);
    private final OrganizationBrandingService orgs = mock(OrganizationBrandingService.class);
    private final RealmEmailBranding branding = new RealmEmailBranding(realms, orgs);

    @AfterEach
    void clear() {
        RequestContextHolder.resetRequestAttributes();
    }

    private void realm(final String displayName, final String logo, final String color) {
        final RealmSettingsDto s = mock(RealmSettingsDto.class);
        when(s.displayName()).thenReturn(displayName);
        when(s.logoUrl()).thenReturn(logo);
        when(s.primaryColor()).thenReturn(color);
        when(realms.get("mf")).thenReturn(s);
    }

    @Test
    void realmBrandingWithoutAnOrganization() {
        realm("Monthfold", "https://cdn.example/mf.png", "#123456");
        assertThat(branding.brandingFor("mf")).isEqualTo(new EmailBranding("Monthfold", "https://cdn.example/mf.png", "#123456"));
    }

    @Test
    void theOrganizationInContextWins_fallingBackToTheRealmPerField() {
        realm("Monthfold", "https://cdn.example/mf.png", "#123456");
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession(true).setAttribute("HELIX_ORGANIZATION_CONTEXT", "mf|o-1");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        when(orgs.get("mf", "o-1")).thenReturn(Optional.of(new OrganizationBrandingService.Branding("Harbor & Pine", null, "#B4532A")));

        assertThat(branding.brandingFor("mf"))
                .isEqualTo(new EmailBranding("Harbor & Pine", "https://cdn.example/mf.png", "#B4532A"));
    }

    @Test
    void helixIamWhenTheRealmCannotBeRead() {
        when(realms.get("mf")).thenThrow(new IllegalStateException("down"));
        assertThat(branding.brandingFor("mf")).isEqualTo(EmailBranding.helixIam());
    }
}
