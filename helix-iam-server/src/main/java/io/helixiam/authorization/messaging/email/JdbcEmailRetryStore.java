/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.helixiam.common.log.LogSafe;
import io.helixiam.persistence.security.AttributeEncryption;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The retry queue in the {@code email_retry} table (Flyway V72), shared by every replica and kept across restarts.
 *
 * <ul>
 *   <li>The rendered message (recipients, subject, HTML and text parts, which carry live links and codes) is stored as
 *       JSON in {@code payload}, encrypted with the database encryption key ({@code DB_ENCRYPTION}, AES-GCM) like the
 *       other secrets. Only the message id, realm, attempt count, times and last failure reason are plain.</li>
 *   <li>{@link #claim} runs {@code SELECT … FOR UPDATE SKIP LOCKED} and moves each claimed row's
 *       {@code next_attempt_at} forward by the lease, in one short transaction: a concurrent claim skips the locked
 *       rows, and once committed the rows are no longer due. The send happens outside any transaction.</li>
 *   <li>{@link #reschedule} and {@link #delete} match the claim token, so a worker whose lease ran out (and whose row
 *       another worker claimed) changes nothing.</li>
 * </ul>
 * Every write runs in its own transaction ({@code REQUIRES_NEW}): the connection pool has auto-commit off, and a
 * queued retry must not depend on the caller's transaction.
 */
public class JdbcEmailRetryStore implements EmailRetryStore {

    private static final Logger LOG = LogManager.getLogger(JdbcEmailRetryStore.class);

    /** The stored form of the message (everything but the id and the expiry, which are columns). */
    record Payload(EmailAddress from, List<EmailAddress> to, EmailAddress replyTo, String subject, String html,
                   String text, Map<String, String> headers) {
    }

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final AttributeEncryption encryption;
    private final ObjectMapper json = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    /**
     * @param encryption the database encryption (null or a converter without key: stored as plain JSON, as every
     *                   other secret is when {@code DB_ENCRYPTION} is unset)
     */
    public JdbcEmailRetryStore(final JdbcTemplate jdbc, final PlatformTransactionManager transactions,
                               final AttributeEncryption encryption) {
        this.jdbc = jdbc;
        this.tx = new TransactionTemplate(transactions);
        this.tx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.encryption = encryption;
    }

    @Override
    public void insert(final Entry entry) {
        final EmailMessage m = entry.message();
        final String payload = encrypt(write(new Payload(m.from(), m.to(), m.replyTo(), m.subject(), m.html(), m.text(),
                m.headers())));
        tx.executeWithoutResult(status -> jdbc.update("""
                INSERT INTO email_retry (message_id, realm_id, payload, attempts, created_at, next_attempt_at,
                                         give_up_at, expires_at, last_reason, claimed_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                ON CONFLICT (message_id) DO UPDATE SET realm_id = EXCLUDED.realm_id, payload = EXCLUDED.payload,
                    attempts = EXCLUDED.attempts, created_at = EXCLUDED.created_at,
                    next_attempt_at = EXCLUDED.next_attempt_at, give_up_at = EXCLUDED.give_up_at,
                    expires_at = EXCLUDED.expires_at, last_reason = EXCLUDED.last_reason, claimed_by = NULL
                """, m.messageId(), entry.realm(), payload, entry.attempts(), entry.createdAt().toEpochMilli(),
                entry.nextAttemptAt().toEpochMilli(), entry.giveUpAt().toEpochMilli(),
                m.expiresAt() == null ? null : m.expiresAt().toEpochMilli(), entry.lastReason()));
    }

    @Override
    public List<Entry> claim(final Instant now, final Duration lease, final int limit, final String claimToken) {
        final long leaseUntil = now.plus(lease).toEpochMilli();
        final List<Row> rows = tx.execute(status -> jdbc.query("""
                WITH due AS (SELECT message_id FROM email_retry WHERE next_attempt_at <= ?
                             ORDER BY next_attempt_at LIMIT ? FOR UPDATE SKIP LOCKED)
                UPDATE email_retry e SET next_attempt_at = ?, claimed_by = ?
                FROM due WHERE e.message_id = due.message_id
                RETURNING e.*""", this::row, now.toEpochMilli(), limit, leaseUntil, claimToken));
        final List<Entry> entries = new ArrayList<>();
        for (final Row row : rows == null ? List.<Row>of() : rows) {
            final Entry entry = toEntry(row);
            if (entry == null) {
                // Unreadable (corrupt, or encrypted with another key): drop it rather than retry it forever.
                LOG.warn("Dropping email retry {}: its stored message cannot be read", LogSafe.sanitize(row.messageId));
                delete(row.messageId, claimToken);
            } else {
                entries.add(entry);
            }
        }
        return entries;
    }

    @Override
    public boolean reschedule(final String messageId, final String claimToken, final int attempts,
                              final Instant nextAttemptAt, final String lastReason) {
        final Integer updated = tx.execute(status -> jdbc.update("UPDATE email_retry SET attempts = ?, "
                        + "next_attempt_at = ?, last_reason = ?, claimed_by = NULL WHERE message_id = ? AND claimed_by = ?",
                attempts, nextAttemptAt.toEpochMilli(), lastReason, messageId, claimToken));
        return updated != null && updated == 1;
    }

    @Override
    public boolean delete(final String messageId, final String claimToken) {
        final Integer deleted = tx.execute(status -> jdbc.update(
                "DELETE FROM email_retry WHERE message_id = ? AND claimed_by = ?", messageId, claimToken));
        return deleted != null && deleted == 1;
    }

    @Override
    public long count() {
        final Long count = jdbc.queryForObject("SELECT count(*) FROM email_retry", Long.class);
        return count == null ? 0 : count;
    }

    private record Row(String messageId, String realm, String payload, int attempts, long createdAt,
                       long nextAttemptAt, long giveUpAt, Long expiresAt, String lastReason) {
    }

    private Row row(final ResultSet rs, final int i) throws SQLException {
        final long expires = rs.getLong("expires_at");
        final Long expiresAt = rs.wasNull() ? null : expires;
        return new Row(rs.getString("message_id"), rs.getString("realm_id"), rs.getString("payload"),
                rs.getInt("attempts"), rs.getLong("created_at"), rs.getLong("next_attempt_at"),
                rs.getLong("give_up_at"), expiresAt, rs.getString("last_reason"));
    }

    private Entry toEntry(final Row row) {
        try {
            final Payload p = json.readValue(decrypt(row.payload), Payload.class);
            final EmailMessage message = new EmailMessage(row.messageId, p.from(), p.to(), p.replyTo(), p.subject(),
                    p.html(), p.text(), p.headers(), row.expiresAt == null ? null : Instant.ofEpochMilli(row.expiresAt));
            return new Entry(row.realm, message, row.attempts, Instant.ofEpochMilli(row.createdAt),
                    Instant.ofEpochMilli(row.nextAttemptAt), Instant.ofEpochMilli(row.giveUpAt), row.lastReason);
        } catch (final JsonProcessingException | RuntimeException e) {
            return null;
        }
    }

    private String write(final Payload payload) {
        try {
            return json.writeValueAsString(payload);
        } catch (final JsonProcessingException e) {
            throw new IllegalStateException("The email could not be stored for a retry", e);
        }
    }

    private String encrypt(final String value) {
        return encryption == null ? value : encryption.convertToDatabaseColumn(value);
    }

    private String decrypt(final String value) {
        return encryption == null ? value : encryption.convertToEntityAttribute(value);
    }
}
