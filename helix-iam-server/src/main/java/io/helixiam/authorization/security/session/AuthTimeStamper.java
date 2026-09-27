/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.session;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.function.LongSupplier;

/**
 * Helix IAM SSO P2: records {@code auth_time} — the epoch-second moment a session became fully
 * authenticated. The authorize endpoint reads it to honour OIDC {@code max_age} (force re-auth when the
 * login is too old) and per-realm SSO max-lifetime (P3); it also feeds the id_token {@code auth_time} claim.
 *
 * <p>Stamped at every login-completion choke point (password success, MFA/flow completion, federated
 * completion) — the same points that resume the saved request ({@link io.helixiam.authorization.security.flow.ResolveSavedRequestRedirect}).
 *
 * <p>A3: the first stamp in a browser session also mints the session's OIDC {@code sid} ({@link #HELIX_SID}),
 * a random opaque id for this SSO session. It survives re-authentication in the same browser session
 * ({@code prompt=login}, {@code max_age}) and ends with it (logout invalidates the HTTP session). Every client
 * authorized in this session gets it in its ID tokens and its back-channel {@code logout_token}s.
 */
public final class AuthTimeStamper {

    /** Session attribute holding the epoch-second auth_time. */
    public static final String HELIX_AUTH_TIME = "HELIX_AUTH_TIME";

    /** Session attribute holding the OIDC {@code sid} of this SSO session (A3). */
    public static final String HELIX_SID = "HELIX_SID";

    private static final SecureRandom RANDOM = new SecureRandom();

    private final LongSupplier nowEpochSeconds;

    public AuthTimeStamper() {
        this(() -> Instant.now().getEpochSecond());
    }

    /** Test seam: inject a fixed clock. */
    AuthTimeStamper(final LongSupplier nowEpochSeconds) {
        this.nowEpochSeconds = nowEpochSeconds;
    }

    /**
     * Stamp the current time as the session's auth_time (creating the session if needed), and give the session
     * its {@code sid} if it has none yet.
     */
    public void stamp(final HttpServletRequest request) {
        final HttpSession session = request.getSession(true);
        session.setAttribute(HELIX_AUTH_TIME, nowEpochSeconds.getAsLong());
        if (!(session.getAttribute(HELIX_SID) instanceof String)) {
            session.setAttribute(HELIX_SID, newSid());
        }
    }

    /** The session's OIDC {@code sid}, or {@code null} when the session never completed a login. */
    public static String readSid(final HttpServletRequest request) {
        final HttpSession session = request.getSession(false);
        return session != null && session.getAttribute(HELIX_SID) instanceof String sid ? sid : null;
    }

    private static String newSid() {
        final byte[] bytes = new byte[24];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
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
