/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.function.LongSupplier;

/**
 * B1: "sign out everywhere else" for browser sessions, whichever store holds them (Redis, the queue store, memory).
 * The user row carries {@code sessions_revoked_at} (epoch millis); a session whose sign-in ({@code auth_time} in millis, or its
 * creation while the sign-in is still in progress) is older than that is ended on its next request by
 * {@link SessionRevocationFilter}. The session that asked is marked as kept ({@link #KEPT_ATTRIBUTE}). A user that no
 * longer exists (deleted account) keeps no session at all.
 */
@Service
public class SessionRevocation {

    /** Session attribute: the revocation moment this session survives (it asked for it). */
    public static final String KEPT_ATTRIBUTE = "HELIX_SESSIONS_KEPT_AT";

    /** What the database says about a user. */
    public record State(boolean exists, Long revokedAt) {

        /** A user that is gone. */
        public static final State GONE = new State(false, null);

        public static State of(final Long revokedAt) {
            return new State(true, revokedAt);
        }
    }

    private final JdbcTemplate jdbc;
    private final LongSupplier clock;

    @org.springframework.beans.factory.annotation.Autowired
    public SessionRevocation(final JdbcTemplate jdbc) {
        this(jdbc, System::currentTimeMillis);
    }

    SessionRevocation(final JdbcTemplate jdbc, final LongSupplier clock) {
        this.jdbc = jdbc;
        this.clock = clock;
    }

    /** Ends every browser session of the user that signed in before now; returns the moment (keep it on your own). */
    @Transactional
    public long revokeAll(final String userId) {
        final long now = clock.getAsLong();
        jdbc.update("UPDATE user_credentials SET sessions_revoked_at = ? WHERE user_id = ?", now, userId);
        return now;
    }

    public State state(final String userId) {
        final List<Long> rows = jdbc.query("SELECT sessions_revoked_at FROM user_credentials WHERE user_id = ?",
                (rs, i) -> {
                    final long v = rs.getLong(1);
                    return rs.wasNull() ? null : v;
                }, userId);
        return rows.isEmpty() ? State.GONE : State.of(rows.get(0));
    }

    /**
     * Whether a session may continue.
     *
     * @param state          the user's state
     * @param authTimeMillis the session's {@code auth_time} (epoch millis), null while the sign-in is in progress
     * @param createdMillis  when the session was created
     * @param keptAt         the revocation this session survives ({@link #KEPT_ATTRIBUTE}), or null
     */
    public static boolean valid(final State state, final Long authTimeMillis, final long createdMillis, final Long keptAt) {
        if (!state.exists()) {
            return false;
        }
        final Long revokedAt = state.revokedAt();
        if (revokedAt == null || (keptAt != null && keptAt >= revokedAt)) {
            return true;
        }
        return (authTimeMillis != null ? authTimeMillis : createdMillis) > revokedAt;
    }
}
