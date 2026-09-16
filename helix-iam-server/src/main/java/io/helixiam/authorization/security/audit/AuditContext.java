package io.helixiam.authorization.security.audit;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Helix IAM E8.5-S4 (Events): small helpers for stamping audit events — the timestamp, the acting
 * principal, and the client IP. Kept separate so the interceptor and the auth-event listener share one
 * definition of "who" and "from where".
 */
public final class AuditContext {

    /** Actor used for admin-API calls that carry no authenticated principal (dev-open admin surface). */
    public static final String ADMIN_API = "admin-api";
    public static final String ANONYMOUS = "anonymous";

    private AuditContext() {
    }

    /** Current time as a second-precision UTC ISO-8601 string. */
    public static String nowIso() {
        return Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
    }

    /** The authenticated principal name, or {@link #ADMIN_API} for the (unauthenticated) admin API. */
    public static String adminActor() {
        final String name = principalName();
        return name != null ? name : ADMIN_API;
    }

    /** The authenticated principal name, or {@link #ANONYMOUS} when there is none. */
    public static String actorOrAnonymous() {
        final String name = principalName();
        return name != null ? name : ANONYMOUS;
    }

    private static String principalName() {
        final Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return null;
        }
        final String name = auth.getName();
        return name == null || "anonymousUser".equals(name) ? null : name;
    }

    /** Client IP: first hop of {@code X-Forwarded-For} if present, else the socket remote address. */
    public static String clientIp(final HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        final String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
