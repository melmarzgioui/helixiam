/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.ratelimit;

import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Auth-hardening (feature 2): the rate-limit filter (429 + Retry-After, pass-through for normal flows). */
class RateLimitFilterTest {

    private RateLimitFilter filter(final long burst) {
        return new RateLimitFilter(true, Map.of("/login", new RateLimiter(burst, burst, 60_000, 1000, () -> 0L)));
    }

    private MockHttpServletRequest postLogin(final String ip) {
        final MockHttpServletRequest req = new MockHttpServletRequest("POST", "/login");
        req.setServletPath("/login");
        req.setRemoteAddr(ip);
        return req;
    }

    @Test
    void throttlesAfterBurst_with429AndRetryAfter() throws Exception {
        final RateLimitFilter filter = filter(1);

        final MockHttpServletResponse first = new MockHttpServletResponse();
        filter.doFilter(postLogin("1.1.1.1"), first, new MockFilterChain());
        assertThat(first.getStatus()).isEqualTo(HttpServletResponse.SC_OK);

        final MockHttpServletResponse second = new MockHttpServletResponse();
        filter.doFilter(postLogin("1.1.1.1"), second, new MockFilterChain());
        assertThat(second.getStatus()).isEqualTo(429);
        assertThat(second.getHeader("Retry-After")).isNotNull();
    }

    @Test
    void doesNotThrottleNonMatchingPath() throws Exception {
        final RateLimitFilter filter = filter(1);
        for (int i = 0; i < 5; i++) {
            final MockHttpServletRequest req = new MockHttpServletRequest("POST", "/something-else");
            req.setServletPath("/something-else");
            final MockFilterChain chain = new MockFilterChain();
            final MockHttpServletResponse res = new MockHttpServletResponse();
            filter.doFilter(req, res, chain);
            assertThat(res.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
            assertThat(chain.getRequest()).isNotNull(); // chain proceeded
        }
    }

    @Test
    void doesNotThrottleGet() throws Exception {
        final RateLimitFilter filter = filter(1);
        for (int i = 0; i < 5; i++) {
            final MockHttpServletRequest req = new MockHttpServletRequest("GET", "/login");
            req.setServletPath("/login");
            final MockHttpServletResponse res = new MockHttpServletResponse();
            filter.doFilter(req, res, new MockFilterChain());
            assertThat(res.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        }
    }

    @Test
    void disabledFilter_passesEverythingThrough() throws Exception {
        final RateLimitFilter filter = new RateLimitFilter(false,
                Map.of("/login", new RateLimiter(1, 1, 60_000, 1000, () -> 0L)));
        for (int i = 0; i < 5; i++) {
            final MockHttpServletResponse res = new MockHttpServletResponse();
            filter.doFilter(postLogin("9.9.9.9"), res, new MockFilterChain());
            assertThat(res.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        }
    }

    @Test
    void aSpoofedXForwardedFor_fromAnUntrustedPeer_doesNotBuyANewBudget() throws Exception {
        final RateLimitFilter filter = filter(1);

        final MockHttpServletRequest a = postLogin("198.51.100.20");
        a.addHeader("X-Forwarded-For", "203.0.113.5");
        filter.doFilter(a, new MockHttpServletResponse(), new MockFilterChain());

        // Same client, a fresh made-up forwarded address: still the same budget.
        final MockHttpServletRequest b = postLogin("198.51.100.20");
        b.addHeader("X-Forwarded-For", "198.51.100.7");
        final MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(b, res, new MockFilterChain());
        assertThat(res.getStatus()).isEqualTo(429);
    }

    @Test
    void honoursXForwardedFor_fromATrustedProxy_forPerIpBudget() throws Exception {
        final RateLimitFilter filter = new RateLimitFilter(true,
                Map.of("/login", new RateLimiter(1, 1, 60_000, 1000, () -> 0L)),
                new io.helixiam.authorization.security.net.ClientIpResolver("10.0.0.0/8"));

        final MockHttpServletRequest a = postLogin("10.0.0.1");
        a.addHeader("X-Forwarded-For", "203.0.113.5");
        filter.doFilter(a, new MockHttpServletResponse(), new MockFilterChain());

        // Same proxy socket, different forwarded client → independent budget, so allowed.
        final MockHttpServletRequest b = postLogin("10.0.0.1");
        b.addHeader("X-Forwarded-For", "198.51.100.7");
        final MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(b, res, new MockFilterChain());
        assertThat(res.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
    }
    /**
     * Task 18: the EUDI wallet endpoints get their own limiter for every method (the request object is a GET), keyed
     * by client IP and the group, not the full path: each transaction has fresh random ids, so a per-path key would
     * never limit anything.
     */
    @Test
    void walletGroup_limitsEveryMethod_perIpAcrossDistinctPaths() throws Exception {
        final RateLimitFilter filter = new RateLimitFilter(true,
                Map.of("/oid4vp", new RateLimiter(2, 2, 60_000, 1000, () -> 0L)), java.util.Set.of("/oid4vp"),
                java.util.List.of(), new io.helixiam.authorization.security.net.ClientIpResolver(""));

        final int[] statuses = new int[3];
        for (int i = 0; i < 3; i++) {
            final MockHttpServletRequest req = new MockHttpServletRequest(i == 1 ? "POST" : "GET",
                    "/oid4vp/eudi/request/id-" + i);
            req.setServletPath("/oid4vp/eudi/request/id-" + i);
            req.setRemoteAddr("2.2.2.2");
            final MockHttpServletResponse res = new MockHttpServletResponse();
            filter.doFilter(req, res, new MockFilterChain());
            statuses[i] = res.getStatus();
        }
        assertThat(statuses).containsExactly(200, 200, 429);

        final MockHttpServletRequest otherIp = new MockHttpServletRequest("GET", "/oid4vp/eudi/request/x");
        otherIp.setServletPath("/oid4vp/eudi/request/x");
        otherIp.setRemoteAddr("3.3.3.3");
        final MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(otherIp, res, new MockFilterChain());
        assertThat(res.getStatus()).isEqualTo(200);
    }

    /**
     * Task 18 fix round 1: a request rule limits what a path prefix cannot describe, e.g. only the broker starts of
     * EUDI wallet providers ({@code GET /broker/<wallet alias>}), keyed by IP + rule.
     */
    @Test
    void aRequestRule_limitsOnlyTheRequestsItApplies_toEveryMethod() throws Exception {
        final RateLimitFilter filter = new RateLimitFilter(true, Map.of(), java.util.Set.of(), java.util.List.of(
                new RateLimitFilter.Rule("wallet-start", r -> r.getServletPath().equals("/broker/eudi"),
                        new RateLimiter(2, 2, 60_000, 1000, () -> 0L))),
                new io.helixiam.authorization.security.net.ClientIpResolver(""));

        final int[] wallet = new int[3];
        for (int i = 0; i < 3; i++) {
            final MockHttpServletRequest req = new MockHttpServletRequest("GET", "/broker/eudi");
            req.setServletPath("/broker/eudi");
            req.setRemoteAddr("4.4.4.4");
            final MockHttpServletResponse res = new MockHttpServletResponse();
            filter.doFilter(req, res, new MockFilterChain());
            wallet[i] = res.getStatus();
        }
        assertThat(wallet).containsExactly(200, 200, 429);

        final MockHttpServletRequest oidc = new MockHttpServletRequest("GET", "/broker/corp");
        oidc.setServletPath("/broker/corp");
        oidc.setRemoteAddr("4.4.4.4");
        final MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(oidc, res, new MockFilterChain());
        assertThat(res.getStatus()).as("another provider's start is not limited").isEqualTo(200);
    }

    /**
     * Final review M2: the wallet's own buckets (the {@code /oid4vp} group and the {@code wallet-start} rule) key on the
     * same trusted-proxy-aware client IP as every other limit: a forged {@code X-Forwarded-For} from a peer that is not
     * a trusted proxy buys no new budget.
     */
    @Test
    void walletGroupAndRule_aSpoofedXForwardedFor_fromAnUntrustedPeer_doesNotBuyANewBudget() throws Exception {
        final RateLimitFilter filter = new RateLimitFilter(true,
                Map.of("/oid4vp", new RateLimiter(1, 1, 60_000, 1000, () -> 0L)), java.util.Set.of("/oid4vp"),
                java.util.List.of(new RateLimitFilter.Rule("wallet-start", r -> r.getServletPath().equals("/broker/eudi"),
                        new RateLimiter(1, 1, 60_000, 1000, () -> 0L))),
                new io.helixiam.authorization.security.net.ClientIpResolver("10.0.0.0/8"));

        for (final String path : java.util.List.of("/oid4vp/eudi/request/a", "/broker/eudi")) {
            final int[] statuses = new int[2];
            for (int i = 0; i < 2; i++) {
                final MockHttpServletRequest req = new MockHttpServletRequest("GET", path);
                req.setServletPath(path);
                req.setRemoteAddr("5.5.5.5"); // not a trusted proxy
                req.addHeader("X-Forwarded-For", "198.51.100." + i); // a fresh forged client per request
                final MockHttpServletResponse res = new MockHttpServletResponse();
                filter.doFilter(req, res, new MockFilterChain());
                statuses[i] = res.getStatus();
            }
            assertThat(statuses).as(path).containsExactly(200, 429);
        }
    }
}
