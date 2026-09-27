/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.render;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.i18n.LocaleContext;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.ViewResolver;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Item 6: renders a themed page (a Thymeleaf template that includes the shared theme fragment) outside Spring MVC —
 * from a servlet filter or a Spring Security handler of a realm request — the way the {@code DispatcherServlet} would:
 * the user's language from the {@link LocaleResolver} (cookie, {@code Accept-Language}, the realm's languages), the
 * {@code hx} page model of the realm (and organization) in context, and links relative to the realm
 * ({@code /realms/{realm}/…}). Must be called while the realm request is in progress, before the response is
 * committed.
 */
@Component
public class ThemedPageRenderer {

    private final ViewResolver views;
    private final LocaleResolver locales;
    private final ThemePageResolver pages;

    public ThemedPageRenderer(@Qualifier("thymeleafViewResolver") final ViewResolver views, final LocaleResolver locales,
                              final ThemePageResolver pages) {
        this.views = views;
        this.locales = locales;
        this.pages = pages;
    }

    /** Renders {@code template} with {@code model} (plus {@code hx}) as the response, with {@code status}. */
    public void render(final String template, final Map<String, ?> model, final int status,
                       final HttpServletRequest request, final HttpServletResponse response) throws Exception {
        request.setAttribute(DispatcherServlet.LOCALE_RESOLVER_ATTRIBUTE, locales);
        final Locale locale = locales.resolveLocale(request);
        final LocaleContext previous = LocaleContextHolder.getLocaleContext();
        LocaleContextHolder.setLocale(locale);
        try {
            final Map<String, Object> all = new LinkedHashMap<>(model);
            all.putIfAbsent(ThemeWebConfig.MODEL_ATTRIBUTE, pages.current(request));
            final View view = views.resolveViewName(template, locale);
            if (view == null) {
                throw new IllegalStateException("No view for template " + template);
            }
            response.setStatus(status);
            response.setHeader("Cache-Control", "no-store");
            view.render(all, request, response);
        } finally {
            LocaleContextHolder.setLocaleContext(previous);
        }
    }
}
