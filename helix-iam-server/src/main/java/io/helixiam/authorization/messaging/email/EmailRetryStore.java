/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Where the emails waiting for a retry are kept ({@link JdbcEmailRetryStore}: the {@code email_retry} table, so a
 * retry survives a restart and is shared by every replica).
 *
 * <p>A worker {@link #claim claims} due entries with a claim token; a claim lasts a lease, after which an unfinished
 * entry (its replica died) becomes due again. {@link #reschedule} and {@link #delete} only act while the caller still
 * holds the claim, so two replicas never both finish the same attempt.
 */
public interface EmailRetryStore {

    /**
     * One email waiting for a retry.
     *
     * @param attempts      delivery attempts made so far (1 after the first, synchronous attempt)
     * @param nextAttemptAt when it is due (while claimed: when the claim expires)
     * @param giveUpAt      no attempt is made at or after this instant
     * @param lastReason    the reason of the last failed attempt
     */
    record Entry(String realm, EmailMessage message, int attempts, Instant createdAt, Instant nextAttemptAt,
                 Instant giveUpAt, String lastReason) {

        public String messageId() {
            return message.messageId();
        }
    }

    /** Stores a new entry (an entry with the same message id is replaced). */
    void insert(Entry entry);

    /**
     * Claims up to {@code limit} entries due at {@code now} for {@code claimToken}: each becomes due again only after
     * {@code lease}. Entries another worker claims at the same time are skipped, never returned twice.
     */
    List<Entry> claim(Instant now, Duration lease, int limit, String claimToken);

    /** Releases a claimed entry for its next attempt; false when the claim was lost (another worker took over). */
    boolean reschedule(String messageId, String claimToken, int attempts, Instant nextAttemptAt, String lastReason);

    /** Removes a claimed, finished entry; false when the claim was lost. */
    boolean delete(String messageId, String claimToken);

    /** How many emails are waiting for a retry (claimed ones included). */
    long count();
}
