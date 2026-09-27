/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.Map;
import java.util.regex.Pattern;

/**
 * Review rc.3 #5: a realm id in an admin path must be 1–100 letters, digits, '.', '_' or '-' (starting with a letter
 * or digit). Anything else is a 400 up front — a 300-character id used to reach the database and fail with a 500.
 */
@Configuration
public class RealmIdInterceptor implements HandlerInterceptor, WebMvcConfigurer {

    static final Pattern REALM_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,99}");

    @Override
    public void addInterceptors(final InterceptorRegistry registry) {
        registry.addInterceptor(this).addPathPatterns("/admin/realms/*", "/admin/realms/*/**");
    }

    @Override
    public boolean preHandle(final HttpServletRequest request, final HttpServletResponse response, final Object handler)
            throws Exception {
        final Object vars = request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
        final Object realm = vars instanceof Map<?, ?> m ? m.get("realmId") : null;
        if (realm == null || REALM_ID.matcher(realm.toString()).matches()) {
            return true;
        }
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"message\":\"A realm id is 1-100 letters, digits, '.', '_' or '-'.\","
                + "\"fieldErrors\":{\"realmId\":\"Invalid realm id.\"}}");
        return false;
    }
}
