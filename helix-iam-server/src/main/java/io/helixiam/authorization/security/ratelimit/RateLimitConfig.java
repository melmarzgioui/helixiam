/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.ratelimit;

import io.helixiam.authorization.security.net.ClientIpResolver;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.security.autoconfigure.web.servlet.SecurityFilterProperties;
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
    private final long walletBurst;
    private final long walletRefillPerMin;
    private final long walletStartBurst;
    private final long walletStartRefillPerMin;
    private final org.springframework.beans.factory.ObjectProvider<io.helixiam.authorization.federation.IdentityProviderRegistry> registry;

    public RateLimitConfig(@Value("${helix.ratelimit.enabled:true}") final boolean enabled,
                           @Value("${helix.ratelimit.login.burst:20}") final long loginBurst,
                           @Value("${helix.ratelimit.login.refill-per-minute:20}") final long loginRefillPerMin,
                           @Value("${helix.ratelimit.token.burst:120}") final long tokenBurst,
                           @Value("${helix.ratelimit.token.refill-per-minute:120}") final long tokenRefillPerMin,
                           // Task 18: the EUDI wallet endpoints' own budget per client IP (two requests per login)
                           @Value("${helix.ratelimit.wallet.burst:120}") final long walletBurst,
                           @Value("${helix.ratelimit.wallet.refill-per-minute:120}") final long walletRefillPerMin,
                           // Task 18 fix round 1: starting a wallet login (each creates a transaction and an EC key)
                           @Value("${helix.ratelimit.wallet-start.burst:30}") final long walletStartBurst,
                           @Value("${helix.ratelimit.wallet-start.refill-per-minute:30}") final long walletStartRefillPerMin,
                           final org.springframework.beans.factory.ObjectProvider<io.helixiam.authorization.federation.IdentityProviderRegistry> registry) {
        this.enabled = enabled;
        this.loginBurst = loginBurst;
        this.loginRefillPerMin = loginRefillPerMin;
        this.tokenBurst = tokenBurst;
        this.tokenRefillPerMin = tokenRefillPerMin;
        this.walletBurst = walletBurst;
        this.walletRefillPerMin = walletRefillPerMin;
        this.walletStartBurst = walletStartBurst;
        this.walletStartRefillPerMin = walletStartRefillPerMin;
        this.registry = registry;
    }

    @Bean
    public RateLimitFilter rateLimitFilter(final ClientIpResolver clientIps) {
        final long minute = 60_000L;
        final RateLimiter loginLimiter = new RateLimiter(loginBurst, loginRefillPerMin, minute);
        final RateLimiter tokenLimiter = new RateLimiter(tokenBurst, tokenRefillPerMin, minute);
        // Insertion order = match precedence (longest prefix still wins inside the filter).
        final Map<String, RateLimiter> limiters = new LinkedHashMap<>();
        limiters.put("/login", loginLimiter);
        limiters.put("/flow", loginLimiter);
        limiters.put("/mfa", loginLimiter); // TOTP, enrolment and recovery-code submits
        limiters.put("/register", loginLimiter);
        limiters.put("/reset/password", loginLimiter);
        limiters.put("/oauth2/token", tokenLimiter);
        // Task 18: the wallet's OpenID4VP endpoints (GET and POST), keyed per IP for the whole group.
        limiters.put("/oid4vp", new RateLimiter(walletBurst, walletRefillPerMin, minute));
        // Task 18 fix round 1: GET /broker/<alias> of an EUDI wallet provider creates a wallet transaction (and an EC
        // key). 30 per minute per client IP (burst 30) is far above what people behind one address start by hand, and
        // keeps one address from filling the transaction store (a 10 000-entry in-memory store at the 300 s default TTL
        // would need ~34 starts a second); a browser also only ever holds one live wallet login (the broker discards
        // the previous one).
        final RateLimitFilter.Rule walletStart = new RateLimitFilter.Rule("wallet-start",
                request -> io.helixiam.authorization.federation.wallet.web.WalletStartRequests.isWalletStart(request,
                        registry.getIfAvailable()),
                new RateLimiter(walletStartBurst, walletStartRefillPerMin, minute));
        return new RateLimitFilter(enabled, limiters, java.util.Set.of("/oid4vp"), java.util.List.of(walletStart),
                clientIps); // the wallet rule and group key on the same trusted-proxy-aware client IP
    }

    @Bean
    public FilterRegistrationBean<RateLimitFilter> rateLimitFilterRegistration(final RateLimitFilter filter) {
        final FilterRegistrationBean<RateLimitFilter> registration = new FilterRegistrationBean<>(filter);
        // After RealmRoutingFilter (DEFAULT_FILTER_ORDER - 10), before the security chain (DEFAULT_FILTER_ORDER).
        registration.setOrder(SecurityFilterProperties.DEFAULT_FILTER_ORDER - 9);
        registration.addUrlPatterns("/*");
        return registration;
    }
}
