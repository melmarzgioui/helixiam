/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** An {@link EmailRetryStore} in memory, with the claim semantics of the JDBC store (unit tests). */
final class InMemoryEmailRetryStore implements EmailRetryStore {

    private final Map<String, Entry> entries = new LinkedHashMap<>();
    private final Map<String, String> claims = new LinkedHashMap<>();

    @Override
    public synchronized void insert(final Entry entry) {
        entries.put(entry.messageId(), entry);
        claims.remove(entry.messageId());
    }

    @Override
    public synchronized List<Entry> claim(final Instant now, final Duration lease, final int limit,
                                          final String claimToken) {
        final List<Entry> due = entries.values().stream().filter(e -> !e.nextAttemptAt().isAfter(now))
                .sorted(Comparator.comparing(Entry::nextAttemptAt)).limit(limit).toList();
        final List<Entry> claimed = new ArrayList<>();
        for (final Entry e : due) {
            final Entry leased = new Entry(e.realm(), e.message(), e.attempts(), e.createdAt(), now.plus(lease),
                    e.giveUpAt(), e.lastReason());
            entries.put(e.messageId(), leased);
            claims.put(e.messageId(), claimToken);
            claimed.add(leased);
        }
        return claimed;
    }

    @Override
    public synchronized boolean reschedule(final String messageId, final String claimToken, final int attempts,
                                           final Instant nextAttemptAt, final String lastReason) {
        if (!claimToken.equals(claims.get(messageId))) {
            return false;
        }
        final Entry e = entries.get(messageId);
        entries.put(messageId, new Entry(e.realm(), e.message(), attempts, e.createdAt(), nextAttemptAt, e.giveUpAt(),
                lastReason));
        claims.remove(messageId);
        return true;
    }

    @Override
    public synchronized boolean delete(final String messageId, final String claimToken) {
        if (!claimToken.equals(claims.get(messageId))) {
            return false;
        }
        claims.remove(messageId);
        return entries.remove(messageId) != null;
    }

    @Override
    public synchronized long count() {
        return entries.size();
    }

    synchronized List<Entry> all() {
        return List.copyOf(entries.values());
    }
}
