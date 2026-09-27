/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging;

import io.helixiam.authorization.theme.EffectiveTheme;
import io.helixiam.authorization.theme.ThemeColor;
import io.helixiam.authorization.theme.ThemeColors;
import io.helixiam.authorization.theme.ThemeDefaults;
import io.helixiam.authorization.theme.render.ThemePage;
import io.helixiam.authorization.theme.render.ThemePageResolver;
import io.helixiam.authorization.theme.render.ThemePages;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Structured theming Task 4: emails carry the same brand as the pages the user came from — the effective theme of the
 * realm, with the organization in context for this sign-in layered on top (field by field): its logo, its light
 * palette (button colour and the text on it, background, card, text, muted text, borders), its footer text in the
 * user's language and its privacy / terms / support links; the name is the organization's, else the realm's display
 * name, else HelixIAM. An uploaded logo ({@code /realms/{r}/theme/assets/…}) is made absolute on {@code idp.base.url}
 * (emails are read outside the site); without one it is left out. Never throws: HelixIAM's look on any failure.
 */
@Component
public class RealmEmailBranding implements EmailBrandingSource {

    private final ThemePageResolver themes;
    private final String idpBaseUrl;

    public RealmEmailBranding(final ThemePageResolver themes, @Value("${idp.base.url:}") final String idpBaseUrl) {
        this.themes = themes;
        this.idpBaseUrl = idpBaseUrl == null ? "" : idpBaseUrl.trim().replaceAll("/+$", "");
    }

    @Override
    public EmailBranding brandingFor(final String realm) {
        if (realm == null) {
            return EmailBranding.helixIam();
        }
        try {
            final ThemePageResolver.Resolved resolved = themes.resolve(realm, currentRequest(),
                    LocaleContextHolder.getLocale());
            return from(resolved.page(), resolved.theme(), resolved.realmDisplayName(), idpBaseUrl);
        } catch (final RuntimeException e) {
            return EmailBranding.helixIam(); // branding never blocks a message
        }
    }

    /** The email brand of a resolved theme (package-visible for tests). */
    static EmailBranding from(final ThemePage page, final EffectiveTheme effective, final String realmDisplayName,
                              final String idpBaseUrl) {
        final ThemeColors colors = effective.theme().colors() == null ? ThemeDefaults.THEME.colors()
                : effective.theme().colors();
        final String name = page.orgName() != null && !page.orgName().isBlank() ? page.orgName()
                : realmDisplayName != null && !realmDisplayName.isBlank() ? realmDisplayName.strip()
                : ThemePages.DEFAULT_BRAND_NAME;
        return new EmailBranding(name, absolute(page.logoUrl(), idpBaseUrl), light(colors, "primary"),
                light(colors, "surfaceRaised"), light(colors, "surface"), light(colors, "surfaceRaised"),
                light(colors, "ink"), light(colors, "inkMuted"), light(colors, "border"), page.footerText(),
                page.privacyUrl(), page.termsUrl(), page.supportUrl());
    }

    private static String light(final ThemeColors colors, final String role) {
        final ThemeColor c = colors.role(role);
        if (c != null && c.light() != null) {
            return c.light();
        }
        final ThemeColor fallback = ThemeDefaults.THEME.colors().role(role);
        return fallback == null ? null : fallback.light();
    }

    /** An https logo as is; the realm's own uploaded asset on the IdP base URL; else none. */
    private static String absolute(final String logo, final String idpBaseUrl) {
        if (logo == null) {
            return null;
        }
        if (logo.startsWith("https://")) {
            return logo;
        }
        return logo.startsWith("/realms/") && !idpBaseUrl.isEmpty() ? idpBaseUrl + logo : null;
    }

    private static HttpServletRequest currentRequest() {
        return RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs
                ? attrs.getRequest() : null;
    }
}
