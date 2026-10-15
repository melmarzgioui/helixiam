/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.web;

import io.helixiam.authorization.federation.wallet.AuthorizationRequestFactory.DcApiRequest;

import java.time.Clock;
import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * The DC API request of each transaction, signed once (review fix): the login page may ask again (the user closed the
 * browser's wallet chooser and tries again), and gets the same request without a new signature. At most
 * {@value #MAX_FETCHES} fetches per transaction (the controller answers {@code 429} after that). Per server instance and
 * in memory: an entry lives until its transaction expires, at most {@code maxEntries} entries are kept (the oldest
 * expiry goes first), so another replica may sign once more and count separately, which only loosens the cap by the
 * replica count.
 */
public class DcApiRequestCache {

    /** Request fetches allowed per transaction. */
    public static final int MAX_FETCHES = 10;
    static final int DEFAULT_MAX_ENTRIES = 10_000;

    private record Entry(DcApiRequest request, Instant expiresAt, int fetches) {
    }

    private final Map<String, Entry> entries = new ConcurrentHashMap<>();
    private final Clock clock;
    private final int maxEntries;

    public DcApiRequestCache() {
        this(Clock.systemUTC(), DEFAULT_MAX_ENTRIES);
    }

    DcApiRequestCache(final Clock clock, final int maxEntries) {
        this.clock = clock;
        this.maxEntries = maxEntries;
    }

    /**
     * The transaction's request: the cached one, or {@code sign}'s (called at most once per live entry). Empty when this
     * transaction has used up its {@value #MAX_FETCHES} fetches. An exception from {@code sign} caches nothing.
     */
    public Optional<DcApiRequest> fetch(final String transactionId, final Instant expiresAt,
                                        final Supplier<DcApiRequest> sign) {
        final Instant now = clock.instant();
        final boolean[] refused = {false};
        final Entry entry = entries.compute(transactionId, (id, old) -> {
            if (old == null || !now.isBefore(old.expiresAt())) {
                return new Entry(sign.get(), expiresAt, 1);
            }
            if (old.fetches() >= MAX_FETCHES) {
                refused[0] = true;
                return old;
            }
            return new Entry(old.request(), old.expiresAt(), old.fetches() + 1);
        });
        if (entries.size() > maxEntries) {
            trim(now);
        }
        return refused[0] ? Optional.empty() : Optional.of(entry.request());
    }

    int size() {
        return entries.size();
    }

    /** Drops expired entries, then the soonest-expiring ones until the cache is within its bound. */
    private void trim(final Instant now) {
        entries.entrySet().removeIf(e -> !now.isBefore(e.getValue().expiresAt()));
        while (entries.size() > maxEntries) {
            String soonest = null;
            Instant at = null;
            for (final Iterator<Map.Entry<String, Entry>> it = entries.entrySet().iterator(); it.hasNext(); ) {
                final Map.Entry<String, Entry> e = it.next();
                if (at == null || e.getValue().expiresAt().isBefore(at)) {
                    at = e.getValue().expiresAt();
                    soonest = e.getKey();
                }
            }
            if (soonest == null) {
                return;
            }
            entries.remove(soonest);
        }
    }
}
