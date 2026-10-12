/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.ratelimit;

import io.helixiam.authorization.security.net.ClientIpResolver;
import io.helixiam.common.log.LogSafe;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Auth-hardening (feature 2): a hand-rolled login rate-limit filter. Throttles by client IP (from
 * {@link ClientIpResolver}: {@code X-Forwarded-For} only from a trusted proxy) on the sensitive POST endpoints — login, OTP/flow submit, {@code /oauth2/token},
 * password-reset request and register — using per-endpoint-group {@link RateLimiter}s. Over-budget requests
 * get {@code 429 Too Many Requests} with a {@code Retry-After} header; every other request passes straight
 * through, so normal flows are untouched. Registered before the auth filter in the login chain.
 *
 * <p>Defaults are generous (configurable via {@code helix.ratelimit.*}); disabled entirely with
 * {@code helix.ratelimit.enabled=false}.
 */
public class RateLimitFilter extends OncePerRequestFilter {

    private static final Logger LOG = LogManager.getLogger(RateLimitFilter.class);

    private final boolean enabled;
    private final ClientIpResolver clientIps;
    /** servlet-path → endpoint-group limiter. The longest matching prefix wins. */
    private final Map<String, RateLimiter> limiters;

    public RateLimitFilter(final boolean enabled, final Map<String, RateLimiter> limiters) {
        this(enabled, limiters, ClientIpResolver.current());
    }

    public RateLimitFilter(final boolean enabled, final Map<String, RateLimiter> limiters,
                           final ClientIpResolver clientIps) {
        this.enabled = enabled;
        this.clientIps = clientIps;
        // Insertion-ordered so the most specific prefixes are listed first.
        this.limiters = new LinkedHashMap<>(limiters);
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
                                    final FilterChain chain) throws ServletException, IOException {
        if (!enabled || !"POST".equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }
        final String path = request.getServletPath();
        final RateLimiter limiter = matchLimiter(path);
        if (limiter == null) {
            chain.doFilter(request, response);
            return;
        }
        final String ip = clientIps.resolve(request);
        final String key = ip + "|" + path;
        final RateLimiter.Decision decision = limiter.check(key);
        if (decision.allowed()) {
            chain.doFilter(request, response);
            return;
        }
        LOG.warn("Rate limit exceeded for {} on {}", LogSafe.sanitize(ip), LogSafe.sanitize(path));
        response.setStatus(429); // 429 Too Many Requests (no SC_ constant in the jakarta servlet API)
        response.setHeader("Retry-After", String.valueOf(decision.retryAfterSeconds()));
        response.setContentType("text/plain;charset=UTF-8");
        response.getWriter().write("Too many requests. Try again in " + decision.retryAfterSeconds() + "s.");
    }

    private RateLimiter matchLimiter(final String path) {
        if (path == null) {
            return null;
        }
        RateLimiter best = null;
        int bestLen = -1;
        for (final Map.Entry<String, RateLimiter> e : limiters.entrySet()) {
            final String prefix = e.getKey();
            if ((path.equals(prefix) || path.startsWith(prefix + "/") || path.startsWith(prefix))
                    && prefix.length() > bestLen) {
                best = e.getValue();
                bestLen = prefix.length();
            }
        }
        return best;
    }
}
