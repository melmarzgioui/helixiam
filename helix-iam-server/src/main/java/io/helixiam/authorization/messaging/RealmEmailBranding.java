/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging;

import io.helixiam.authorization.amqp.realm.RealmSettingsDto;
import io.helixiam.authorization.security.realm.OrganizationContext;
import io.helixiam.authorization.security.realm.RealmSettingsResolver;
import io.helixiam.authorization.service.org.OrganizationBrandingService;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Optional;

/**
 * Emails carry the same brand as the pages the user came from: the organization in context for this sign-in (its
 * name, logo and colour), else the realm's display name, logo and primary colour, else HelixIAM.
 */
@Component
public class RealmEmailBranding implements EmailBrandingSource {

    private final RealmSettingsResolver realms;
    private final OrganizationBrandingService organizations;

    public RealmEmailBranding(final RealmSettingsResolver realms, final OrganizationBrandingService organizations) {
        this.realms = realms;
        this.organizations = organizations;
    }

    @Override
    public EmailBranding brandingFor(final String realm) {
        try {
            final RealmSettingsDto settings = realm == null ? null : realms.get(realm);
            final EmailBranding realmBrand = settings == null ? EmailBranding.helixIam()
                    : new EmailBranding(settings.displayName(), settings.logoUrl(), settings.primaryColor());
            return organization(realm)
                    .map(o -> new EmailBranding(o.displayName(),
                            o.logoUrl() != null ? o.logoUrl() : realmBrand.logoUrl(),
                            o.primaryColor() != null ? o.primaryColor() : realmBrand.color()))
                    .orElse(realmBrand);
        } catch (final RuntimeException e) {
            return EmailBranding.helixIam(); // branding never blocks a message
        }
    }

    private Optional<OrganizationBrandingService.Branding> organization(final String realm) {
        if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs)) {
            return Optional.empty();
        }
        return OrganizationContext.current(attrs.getRequest(), realm).flatMap(id -> organizations.get(realm, id));
    }
}
