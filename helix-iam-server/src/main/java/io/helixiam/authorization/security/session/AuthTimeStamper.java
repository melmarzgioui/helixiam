package io.helixiam.authorization.security.session;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.time.Instant;
import java.util.function.LongSupplier;

/**
 * Helix IAM SSO P2: records {@code auth_time} — the epoch-second moment a session became fully
 * authenticated. The authorize endpoint reads it to honour OIDC {@code max_age} (force re-auth when the
 * login is too old) and per-realm SSO max-lifetime (P3); it also feeds the id_token {@code auth_time} claim.
 *
 * <p>Stamped at every login-completion choke point (password success, MFA/flow completion, federated
 * completion) — the same points that resume the saved request ({@link io.helixiam.authorization.security.flow.ResolveSavedRequestRedirect}).
 */
public final class AuthTimeStamper {

    /** Session attribute holding the epoch-second auth_time. */
    public static final String HELIX_AUTH_TIME = "HELIX_AUTH_TIME";

    private final LongSupplier nowEpochSeconds;

    public AuthTimeStamper() {
        this(() -> Instant.now().getEpochSecond());
    }

    /** Test seam: inject a fixed clock. */
    AuthTimeStamper(final LongSupplier nowEpochSeconds) {
        this.nowEpochSeconds = nowEpochSeconds;
    }

    /** Stamp the current time as the session's auth_time (creating the session if needed). */
    public void stamp(final HttpServletRequest request) {
        request.getSession(true).setAttribute(HELIX_AUTH_TIME, nowEpochSeconds.getAsLong());
    }

    /** The session's auth_time in epoch seconds, or {@code null} when unset / no session. */
    public Long read(final HttpServletRequest request) {
        final HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        final Object value = session.getAttribute(HELIX_AUTH_TIME);
        return value instanceof Long longValue ? longValue : null;
    }
}
