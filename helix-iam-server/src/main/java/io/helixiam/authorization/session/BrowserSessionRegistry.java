/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import io.helixiam.authorization.security.session.AuthTimeStamper;
import io.helixiam.common.log.LogSafe;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.function.LongSupplier;

/**
 * rc.6 item 7b: which browsers a user is signed in with, whichever store holds the HTTP sessions (Redis cannot list a
 * user's sessions, the queue store can). One row per browser sign-in, keyed by its OIDC {@code sid}
 * ({@link AuthTimeStamper#HELIX_SID}): the HTTP session that carries it now (the id changes at sign-in and step-up),
 * the device it signed in from ({@link DeviceLabel}, never the raw header) and when.
 *
 * <p>{@link SessionRevocationFilter} calls {@link #touch} on every request of a signed-in browser; it writes only when
 * the sid, the HTTP session id or the user changed ({@link #REGISTERED_ATTRIBUTE}). The session store stays the
 * truth: {@link AccountSessionService} checks each row against it and {@link #remove removes} rows whose session is
 * gone. Rows of a deleted user go with the user ({@code ON DELETE CASCADE}).
 */
@Service
public class BrowserSessionRegistry {

    /** Session attribute: the {@code sid|http session id|user id} this session was last recorded as. */
    public static final String REGISTERED_ATTRIBUTE = "HELIX_BROWSER_SESSION_REGISTERED";

    private static final Logger LOG = LogManager.getLogger(BrowserSessionRegistry.class);

    /** One recorded browser sign-in. */
    public record Entry(String sid, String userId, String httpSessionId, DeviceLabel device, Instant signedInAt) {
    }

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final LongSupplier clock;

    @Autowired
    public BrowserSessionRegistry(final JdbcTemplate jdbc, final PlatformTransactionManager transactions) {
        this(jdbc, transactions, System::currentTimeMillis);
    }

    BrowserSessionRegistry(final JdbcTemplate jdbc, final PlatformTransactionManager transactions,
                           final LongSupplier clock) {
        this.jdbc = jdbc;
        this.tx = new TransactionTemplate(transactions);
        this.clock = clock;
    }

    /**
     * Records the signed-in browser of this request for {@code userId}, if the session has a {@code sid} (the sign-in
     * completed) and it is not recorded like this already. Never fails the request.
     */
    public void touch(final HttpServletRequest request, final HttpSession session, final String userId) {
        if (!(session.getAttribute(AuthTimeStamper.HELIX_SID) instanceof String sid) || userId == null) {
            return;
        }
        final String key = sid + "|" + session.getId() + "|" + userId;
        if (key.equals(session.getAttribute(REGISTERED_ATTRIBUTE))) {
            return;
        }
        try {
            record(sid, userId, session.getId(), DeviceLabel.parse(request.getHeader(HttpHeaders.USER_AGENT)));
        } catch (final RuntimeException e) {
            // Not retried on every request: the session list then falls back to the session's apps.
            LOG.warn("Could not record the browser session of user {}: {}", LogSafe.sanitize(userId),
                    LogSafe.sanitize(e.getClass().getName()));
        }
        session.setAttribute(REGISTERED_ATTRIBUTE, key);
    }

    /** Inserts or updates the row of {@code sid}; a sid that changed hands (another user) starts a new sign-in. */
    void record(final String sid, final String userId, final String httpSessionId, final DeviceLabel device) {
        final long now = clock.getAsLong();
        tx.executeWithoutResult(status -> jdbc.update("""
                INSERT INTO browser_session (sid, user_id, http_session_id, browser, os, signed_in_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT (sid) DO UPDATE SET
                    signed_in_at = CASE WHEN browser_session.user_id = EXCLUDED.user_id
                                        THEN browser_session.signed_in_at ELSE EXCLUDED.signed_in_at END,
                    user_id = EXCLUDED.user_id,
                    http_session_id = EXCLUDED.http_session_id,
                    browser = EXCLUDED.browser,
                    os = EXCLUDED.os
                """, sid, userId, httpSessionId, device.browser(), device.os(), now));
    }

    /** Every recorded browser sign-in of {@code userId}. */
    public List<Entry> forUser(final String userId) {
        return jdbc.query("SELECT sid, user_id, http_session_id, browser, os, signed_in_at FROM browser_session"
                + " WHERE user_id = ?", (rs, i) -> new Entry(rs.getString(1), rs.getString(2), rs.getString(3),
                new DeviceLabel(rs.getString(4), rs.getString(5)), Instant.ofEpochMilli(rs.getLong(6))), userId);
    }

    /** The browser sign-in {@code sid}, only if it is {@code userId}'s. */
    public Optional<Entry> find(final String userId, final String sid) {
        return forUser(userId).stream().filter(e -> e.sid().equals(sid)).findFirst();
    }

    /** Forgets the browser sign-in {@code sid} of {@code userId}. */
    public void remove(final String userId, final String sid) {
        tx.executeWithoutResult(status -> jdbc.update("DELETE FROM browser_session WHERE sid = ? AND user_id = ?",
                sid, userId));
    }
}
