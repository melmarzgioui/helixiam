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
    void honoursXForwardedFor_forPerIpBudget() throws Exception {
        final RateLimitFilter filter = filter(1);

        final MockHttpServletRequest a = postLogin("10.0.0.1");
        a.addHeader("X-Forwarded-For", "203.0.113.5, 10.0.0.1");
        filter.doFilter(a, new MockHttpServletResponse(), new MockFilterChain());

        // Same proxy socket, different forwarded client → independent budget, so allowed.
        final MockHttpServletRequest b = postLogin("10.0.0.1");
        b.addHeader("X-Forwarded-For", "198.51.100.7, 10.0.0.1");
        final MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(b, res, new MockFilterChain());
        assertThat(res.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
    }
}
