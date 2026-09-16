/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.ratelimit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Auth-hardening (feature 2): wires the {@link RateLimitFilter} ahead of the Spring Security filter chain
 * (just after {@code RealmRoutingFilter}, so it runs <em>before</em> authentication) via a
 * {@link FilterRegistrationBean}. This keeps {@code SecurityConfig} untouched while still satisfying the
 * "register before auth" requirement.
 *
 * <p>Limits are config-driven with generous defaults so normal interactive flows never trip them:
 * each protected endpoint group gets {@code burst} tokens refilling {@code refill} tokens per minute, keyed
 * per client IP. Disable with {@code helix.ratelimit.enabled=false}.
 */
@Configuration
public class RateLimitConfig {

    private final boolean enabled;
    private final long loginBurst;
    private final long loginRefillPerMin;
    private final long tokenBurst;
    private final long tokenRefillPerMin;

    public RateLimitConfig(@Value("${helix.ratelimit.enabled:true}") final boolean enabled,
                           @Value("${helix.ratelimit.login.burst:20}") final long loginBurst,
                           @Value("${helix.ratelimit.login.refill-per-minute:20}") final long loginRefillPerMin,
                           @Value("${helix.ratelimit.token.burst:120}") final long tokenBurst,
                           @Value("${helix.ratelimit.token.refill-per-minute:120}") final long tokenRefillPerMin) {
        this.enabled = enabled;
        this.loginBurst = loginBurst;
        this.loginRefillPerMin = loginRefillPerMin;
        this.tokenBurst = tokenBurst;
        this.tokenRefillPerMin = tokenRefillPerMin;
    }

    @Bean
    public RateLimitFilter rateLimitFilter() {
        final long minute = 60_000L;
        final RateLimiter loginLimiter = new RateLimiter(loginBurst, loginRefillPerMin, minute);
        final RateLimiter tokenLimiter = new RateLimiter(tokenBurst, tokenRefillPerMin, minute);
        // Insertion order = match precedence (longest prefix still wins inside the filter).
        final Map<String, RateLimiter> limiters = new LinkedHashMap<>();
        limiters.put("/login", loginLimiter);
        limiters.put("/flow", loginLimiter);
        limiters.put("/register", loginLimiter);
        limiters.put("/reset/password", loginLimiter);
        limiters.put("/oauth2/token", tokenLimiter);
        return new RateLimitFilter(enabled, limiters);
    }

    @Bean
    public FilterRegistrationBean<RateLimitFilter> rateLimitFilterRegistration(final RateLimitFilter filter) {
        final FilterRegistrationBean<RateLimitFilter> registration = new FilterRegistrationBean<>(filter);
        // After RealmRoutingFilter (DEFAULT_FILTER_ORDER - 10), before the security chain (DEFAULT_FILTER_ORDER).
        registration.setOrder(SecurityProperties.DEFAULT_FILTER_ORDER - 9);
        registration.addUrlPatterns("/*");
        return registration;
    }
}
