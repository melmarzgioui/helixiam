/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.adminrbac;

import io.helixiam.authorization.service.adminrbac.PrivilegedPrincipalGuard;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** Registers {@link PrivilegedPrincipalInterceptor} on the admin user and client routes (security review H5). */
@Configuration
public class PrivilegedPrincipalWebConfig implements WebMvcConfigurer {

    private final PrivilegedPrincipalGuard guard;

    public PrivilegedPrincipalWebConfig(final PrivilegedPrincipalGuard guard) {
        this.guard = guard;
    }

    @Override
    public void addInterceptors(final InterceptorRegistry registry) {
        registry.addInterceptor(new PrivilegedPrincipalInterceptor(guard))
                .addPathPatterns("/admin/realms/*/users/*", "/admin/realms/*/users/*/**",
                        "/admin/realms/*/clients/*", "/admin/realms/*/clients/*/**");
    }
}
