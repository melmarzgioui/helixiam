/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.account.console;

import io.helixiam.authorization.security.mfa.MfaEnforcementFilter;
import io.helixiam.authorization.service.mfa.MfaPolicyService;
import io.helixiam.authorization.service.mfa.TotpService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * B1: the account console pages ({@link AccountConsolePage}) are held behind the second factor. A user who has an
 * authenticator app, or whose realm requires one, and has not passed it in this sign-in is sent to it first
 * ({@link MfaEnforcementFilter#gate}) — the same rule {@code /oauth2/authorize} applies — and comes back afterwards.
 */
@Configuration
public class AccountConsoleWebConfig implements WebMvcConfigurer {

    private final MfaEnforcementFilter mfaGate;

    public AccountConsoleWebConfig(final MfaPolicyService policy, final TotpService totp) {
        this.mfaGate = new MfaEnforcementFilter(policy, totp);
    }

    @Override
    public void addInterceptors(final InterceptorRegistry registry) {
        registry.addInterceptor(new HandlerInterceptor() {
            @Override
            public boolean preHandle(final HttpServletRequest request, final HttpServletResponse response,
                                     final Object handler) throws Exception {
                if (handler instanceof HandlerMethod method
                        && method.getBeanType().isAnnotationPresent(AccountConsolePage.class)) {
                    return !mfaGate.gate(request, response);
                }
                return true;
            }
        }).addPathPatterns("/account", "/account/**");
    }
}
