/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.List;
import java.util.Locale;

/**
 * Bounced addresses on the user ({@code user_credentials.email_bounced_at} and {@code email_bounced_address}). A bounce
 * shows ({@code emailBounced} in the admin user API) only while the bounced address is still the user's address, so a
 * changed address is never shown as bounced; {@link #clear} also removes it when the address changes or is verified
 * again.
 */
public class JdbcBounceRecorder implements BounceRecorder {

    /** Emails sent outside a realm (the platform-level signup and reset notifications) are the master realm's. */
    static final String DEFAULT_REALM = "master";

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;

    public JdbcBounceRecorder(final JdbcTemplate jdbc, final PlatformTransactionManager transactions) {
        this.jdbc = jdbc;
        this.tx = new TransactionTemplate(transactions);
    }

    @Override
    public List<String> markBounced(final String realm, final String address, final Instant at) {
        if (address == null || address.isBlank()) {
            return List.of();
        }
        final String normalised = address.trim().toLowerCase(Locale.ROOT);
        final List<String> users = tx.execute(status -> jdbc.queryForList("""
                UPDATE user_credentials SET email_bounced_at = ?, email_bounced_address = ?
                WHERE realm_id = ? AND lower(email) = ? RETURNING user_id""", String.class, at.toEpochMilli(),
                normalised, realm == null ? DEFAULT_REALM : realm, normalised));
        return users == null ? List.of() : users;
    }

    /** Clears a bounce on {@code userId}: its address changed, or was verified again. Joins the caller's transaction. */
    public void clear(final String userId) {
        if (userId == null) {
            return;
        }
        tx.executeWithoutResult(status -> jdbc.update("UPDATE user_credentials SET email_bounced_at = NULL, "
                + "email_bounced_address = NULL WHERE user_id = ? AND email_bounced_at IS NOT NULL", userId));
    }
}
