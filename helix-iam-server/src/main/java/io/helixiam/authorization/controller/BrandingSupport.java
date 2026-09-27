/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller;

import io.helixiam.authorization.amqp.realm.RealmSettingsDto;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.security.realm.RealmSettingsResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.ui.Model;

/**
 * Exposes per-realm login theming (B2) to any IdP-served page — the login, device {@code /activate}, and
 * consent screens all render the same brand. When a realm hasn't customised its branding (or settings can't
 * be loaded), the model attributes stay null and the template falls back to the built-in Helix IAM theme.
 */
@Component
public class BrandingSupport {

    @Autowired(required = false)
    private RealmSettingsResolver realmSettingsResolver;

    @Autowired(required = false)
    private io.helixiam.authorization.service.org.OrganizationBrandingService organizationBranding;

    @Autowired(required = false)
    private io.helixiam.authorization.theme.ThemeService themeService;

    /**
     * Populates {@code branding*} attributes for the current realm, overridden by the organization in context
     * (if any); best-effort, never throws.
     */
    public void apply(final Model model) {
        if (realmSettingsResolver == null) {
            return;
        }
        try {
            final RealmSettingsDto s = realmSettingsResolver.get(RealmContextHolder.get());
            if (s == null) {
                return;
            }
            model.addAttribute("brandingLogo", blankToNull(s.logoUrl()));
            model.addAttribute("brandingPrimaryColor", blankToNull(s.primaryColor()));
            model.addAttribute("brandingBackgroundColor", blankToNull(s.backgroundColor()));
            model.addAttribute("brandingWelcomeText", blankToNull(s.welcomeText()));
            // Review C1: only custom CSS that passes the CURRENT validator is ever rendered — taken from the effective
            // theme (re-checked on every resolve), never the raw stored or realm-settings value.
            model.addAttribute("brandingCustomCss", themeService == null ? null
                    : blankToNull(themeService.effectiveTheme(RealmContextHolder.get(), java.util.Optional.empty())
                            .theme().customCss()));
        } catch (final RuntimeException ignored) {
            // Branding must never block sign-in.
        }
        applyOrganization(model);
    }

    /**
     * 1.0 item 7: when an organization is in context for this sign-in ({@code organization} authorize hint), its
     * name, logo and colour take precedence over the realm's.
     */
    private void applyOrganization(final Model model) {
        if (organizationBranding == null
                || !(org.springframework.web.context.request.RequestContextHolder.getRequestAttributes()
                        instanceof org.springframework.web.context.request.ServletRequestAttributes attrs)) {
            return;
        }
        try {
            final String realm = RealmContextHolder.get();
            io.helixiam.authorization.security.realm.OrganizationContext.current(attrs.getRequest(), realm)
                    .flatMap(orgId -> organizationBranding.get(realm, orgId))
                    .ifPresent(b -> {
                        model.addAttribute("brandingOrgName", b.displayName());
                        if (b.logoUrl() != null) {
                            model.addAttribute("brandingLogo", b.logoUrl());
                        }
                        if (b.primaryColor() != null) {
                            model.addAttribute("brandingPrimaryColor", b.primaryColor());
                        }
                    });
        } catch (final RuntimeException ignored) {
            // Branding must never block sign-in.
        }
    }

    private static String blankToNull(final String v) {
        return v == null || v.isBlank() ? null : v;
    }
}
