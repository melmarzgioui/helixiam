/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.render;

import io.helixiam.authorization.amqp.realm.RealmSettingsDto;
import io.helixiam.common.log.LogSafe;
import io.helixiam.authorization.security.realm.OrganizationContext;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.security.realm.RealmSettingsResolver;
import io.helixiam.authorization.service.org.OrganizationBrandingService;
import io.helixiam.authorization.theme.ThemePalette;
import io.helixiam.authorization.theme.EffectiveTheme;
import io.helixiam.authorization.theme.ThemeDefaults;
import io.helixiam.authorization.theme.ThemeService;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * Resolves the {@link ThemePage} of the current request: the realm from {@link RealmContextHolder}, the organization
 * in context from {@link OrganizationContext} (field-by-field precedence organization → realm → default), the locale
 * from the request. Never throws — theming must never block sign-in; on any failure the HelixIAM default is used.
 */
@Component
public class ThemePageResolver {

    /** The realm pages fall back to outside a realm-routed request. */
    static final String FALLBACK_REALM = "master";

    private static final Logger LOG = LogManager.getLogger(ThemePageResolver.class);

    private final ThemeService themes;
    private final ThemeStylesheet stylesheets;
    private final ObjectProvider<OrganizationBrandingService> organizations;
    private final ObjectProvider<RealmSettingsResolver> settings;

    public ThemePageResolver(final ThemeService themes, final ThemeStylesheet stylesheets,
                             final ObjectProvider<OrganizationBrandingService> organizations,
                             final ObjectProvider<RealmSettingsResolver> settings) {
        this.themes = themes;
        this.stylesheets = stylesheets;
        this.organizations = organizations;
        this.settings = settings;
    }

    /** The page model for {@code request} (the current realm and organization, the request's locale). */
    public ThemePage current(final HttpServletRequest request) {
        final String realm = Optional.ofNullable(RealmContextHolder.get()).orElse(FALLBACK_REALM);
        return resolve(realm, request, LocaleContextHolder.getLocale()).page();
    }

    /**
     * The page model and the effective theme of {@code realm} (with the organization in context of {@code request},
     * which may be null) in {@code locale} — for pages and for emails (Task 4: emails carry the same logo, colours,
     * texts and footer). Never throws: on any failure the HelixIAM default is used.
     */
    public Resolved resolve(final String realm, final HttpServletRequest request, final Locale locale) {
        try {
            final Optional<String> orgId = OrganizationContext.current(request, realm);
            final Optional<OrganizationBrandingService.Branding> org = orgId.flatMap(id ->
                    Optional.ofNullable(organizations.getIfAvailable()).flatMap(o -> o.get(realm, id)));
            final Optional<String> inRealm = org.isPresent() ? orgId : Optional.empty();
            final EffectiveTheme effective = themes.effectiveTheme(realm, inRealm);
            final ThemeStylesheet.Rendered css = stylesheets.forRealm(realm, inRealm);
            final String realmName = displayName(realm);
            return new Resolved(ThemePages.build(effective, realm, inRealm.orElse(null),
                    org.map(OrganizationBrandingService.Branding::displayName).orElse(null), realmName,
                    locale, css.version()), effective, realmName);
        } catch (final RuntimeException e) {
            LOG.warn("Theme for realm {} could not be resolved; the HelixIAM default is used: {}", LogSafe.sanitize(realm),
                    LogSafe.sanitize(e.toString()));
            return new Resolved(defaults(realm, locale), defaultTheme(), null);
        }
    }

    /**
     * A resolved theme: the page model, the effective theme (colours), and the realm's display name (or null).
     */
    public record Resolved(ThemePage page, EffectiveTheme theme, String realmDisplayName) {
    }

    private static EffectiveTheme defaultTheme() {
        return new EffectiveTheme(ThemePalette.resolve(ThemeDefaults.THEME), "default", Set.of(), Set.of());
    }

    /** The HelixIAM default page model (no realm theme). */
    public static ThemePage defaults(final String realm, final Locale locale) {
        return ThemePages.build(defaultTheme(), realm, null, null, null, locale, "default");
    }

    private String displayName(final String realm) {
        final RealmSettingsResolver resolver = settings.getIfAvailable();
        if (resolver == null) {
            return null;
        }
        final RealmSettingsDto dto = resolver.get(realm);
        return dto == null ? null : dto.displayName();
    }
}
