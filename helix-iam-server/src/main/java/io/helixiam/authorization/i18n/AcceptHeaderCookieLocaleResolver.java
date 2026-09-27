/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.i18n;

import java.util.List;
import java.util.Locale;
import java.util.function.Function;

import org.springframework.lang.Nullable;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Helix IAM i18n — a {@link CookieLocaleResolver} that, when no language cookie is present, negotiates
 * the locale from the request's {@code Accept-Language} header (via the parent's
 * {@code defaultLocaleFunction} hook) instead of falling straight back to a fixed default. The result
 * is constrained to the platform's {@link I18nConfig#SUPPORTED supported languages}; any unsupported
 * request degrades to {@code en}.
 *
 * <p>Resolution order for a given request (all handled here or by the parent):
 * <ol>
 *   <li>{@code HELIX_LOCALE} cookie (set by a {@code ?lang=} switch via {@code LocaleChangeInterceptor});</li>
 *   <li>{@code Accept-Language}, restricted to the supported set;</li>
 *   <li>{@code en}.</li>
 * </ol>
 *
 * <p>Delegating cookie handling to the parent means the post-switch request attribute the
 * {@code LocaleChangeInterceptor} writes is honoured for the rest of the same request — we do not
 * re-parse cookies ourselves.
 *
 * <p>Single constructor (default) — exempt from the multi-constructor {@code @Autowired} trap.
 */
public class AcceptHeaderCookieLocaleResolver extends CookieLocaleResolver {

    /** The current realm's (and organization's) supported locales, or null when there is no realm theme to apply. */
    private Function<HttpServletRequest, List<String>> realmLocales;

    public AcceptHeaderCookieLocaleResolver() {
        super(I18nConfig.LOCALE_COOKIE);
        // No cookie? Use the Accept-Language locale; resolveLocale narrows it to what the realm (or HelixIAM) offers.
        setDefaultLocaleFunction(HttpServletRequest::getLocale);
    }

    /**
     * Structured theming: the realm theme's {@code layout.supportedLocales} decide which languages a realm offers
     * (an English-only realm serves English to a Dutch browser; a realm may list a language HelixIAM has no bundle
     * for — its theme texts are then used, with the built-in messages in English).
     */
    public void setRealmLocales(final Function<HttpServletRequest, List<String>> realmLocales) {
        this.realmLocales = realmLocales;
    }

    @Override
    public Locale resolveLocale(final HttpServletRequest request) {
        // Parent applies: cookie (or the interceptor's same-request attribute) -> defaultLocaleFunction.
        final Locale requested = super.resolveLocale(request);
        final List<String> offered = offered(request);
        if (offered == null || offered.isEmpty()) {
            // Re-clamp to the supported set so a stale/hand-set cookie like "fr" still degrades to en.
            return supportedOrDefault(requested);
        }
        if (requested != null) {
            for (final String tag : offered) {
                if (tag.equalsIgnoreCase(requested.toLanguageTag())) {
                    return Locale.forLanguageTag(tag);
                }
            }
            for (final String tag : offered) {
                if (Locale.forLanguageTag(tag).getLanguage().equals(requested.getLanguage())) {
                    return Locale.forLanguageTag(tag);
                }
            }
        }
        return Locale.forLanguageTag(offered.get(0));
    }

    private List<String> offered(final HttpServletRequest request) {
        if (realmLocales == null) {
            return null;
        }
        try {
            return realmLocales.apply(request);
        } catch (final RuntimeException e) {
            return null; // a theme lookup problem must never break a page
        }
    }

    /** Matches the requested locale's language against {@link I18nConfig#SUPPORTED}; else {@code en}. */
    static Locale supportedOrDefault(@Nullable final Locale requested) {
        if (requested == null || requested.getLanguage().isEmpty()) {
            return Locale.ENGLISH;
        }
        for (final Locale supported : I18nConfig.SUPPORTED) {
            if (supported.getLanguage().equals(requested.getLanguage())) {
                return supported;
            }
        }
        return Locale.ENGLISH;
    }
}
