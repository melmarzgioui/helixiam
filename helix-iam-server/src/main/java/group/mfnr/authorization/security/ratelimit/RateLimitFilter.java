package group.mfnr.authorization.security.ratelimit;

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
 * Auth-hardening (feature 2): a hand-rolled login rate-limit filter. Throttles by client IP (honouring
 * {@code X-Forwarded-For}) on the sensitive POST endpoints — login, OTP/flow submit, {@code /oauth2/token},
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
    /** servlet-path → endpoint-group limiter. The longest matching prefix wins. */
    private final Map<String, RateLimiter> limiters;

    public RateLimitFilter(final boolean enabled, final Map<String, RateLimiter> limiters) {
        this.enabled = enabled;
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
        final String key = clientIp(request) + "|" + path;
        final RateLimiter.Decision decision = limiter.check(key);
        if (decision.allowed()) {
            chain.doFilter(request, response);
            return;
        }
        LOG.warn("Rate limit exceeded for {} on {}", clientIp(request), path);
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

    /** Honour {@code X-Forwarded-For} (first hop), else {@code X-Real-IP}, else the socket address. */
    static String clientIp(final HttpServletRequest request) {
        final String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            final int comma = forwarded.indexOf(',');
            return (comma > 0 ? forwarded.substring(0, comma) : forwarded).trim();
        }
        final String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp.trim();
        }
        return request.getRemoteAddr();
    }
}
