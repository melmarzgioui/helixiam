/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.render;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Puts the {@link ThemePage} ({@value #MODEL_ATTRIBUTE}) into the model of every rendered page, so every user-facing
 * template can include the shared theme fragment without each controller having to remember it. A controller that
 * already set the attribute (the preview) keeps its own; redirects and REST responses are left alone.
 */
@Configuration
public class ThemeWebConfig implements WebMvcConfigurer {

    /** The model attribute the templates read ({@code ${hx.logoUrl}}, …). */
    public static final String MODEL_ATTRIBUTE = "hx";

    private final ThemePageResolver pages;

    public ThemeWebConfig(final ThemePageResolver pages) {
        this.pages = pages;
    }

    /**
     * Item 6: themed error pages for browsers on realm endpoints ({@link ProtocolErrorPageFilter}), inside the realm
     * routing and ahead of Spring Security, so the OAuth / OIDC endpoints' {@code sendError} is caught.
     */
    @Bean
    public FilterRegistrationBean<ProtocolErrorPageFilter> protocolErrorPageFilter(final ThemedPageRenderer renderer) {
        final FilterRegistrationBean<ProtocolErrorPageFilter> registration =
                new FilterRegistrationBean<>(new ProtocolErrorPageFilter(renderer));
        registration.setOrder(SecurityProperties.DEFAULT_FILTER_ORDER - 8);
        registration.addUrlPatterns("/*");
        return registration;
    }

    @Override
    public void addInterceptors(final InterceptorRegistry registry) {
        registry.addInterceptor(new HandlerInterceptor() {
            @Override
            public void postHandle(final HttpServletRequest request, final HttpServletResponse response,
                                   final Object handler, final ModelAndView mav) {
                if (mav == null || mav.getModelMap().containsAttribute(MODEL_ATTRIBUTE)) {
                    return;
                }
                final String view = mav.getViewName();
                if (view != null && (view.startsWith("redirect:") || view.startsWith("forward:"))) {
                    return;
                }
                if ((view == null && mav.getView() == null)
                        || mav.getView() instanceof org.springframework.web.servlet.view.RedirectView) {
                    return;
                }
                mav.addObject(MODEL_ATTRIBUTE, pages.current(request));
            }
        }).excludePathPatterns("/admin/**");
    }
}
