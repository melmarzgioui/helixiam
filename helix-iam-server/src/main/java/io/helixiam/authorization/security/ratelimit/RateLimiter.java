/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.ratelimit;

import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Auth-hardening (feature 2): an in-memory, per-key {@link TokenBucket} registry. Keys are typically
 * {@code clientIp + "|" + endpointGroup} so each IP gets an independent budget per protected endpoint.
 * Buckets are created lazily and held in a {@link ConcurrentHashMap}; a coarse size cap with oldest-touch
 * eviction keeps memory bounded under a flood of distinct IPs. The clock is injectable for tests.
 */
public final class RateLimiter {

    private final long capacity;
    private final long refillTokens;
    private final long refillIntervalMillis;
    private final int maxBuckets;
    private final LongSupplier clock;
    private final ConcurrentHashMap<String, Entry> buckets = new ConcurrentHashMap<>();

    public RateLimiter(final long capacity, final long refillTokens, final long refillIntervalMillis) {
        this(capacity, refillTokens, refillIntervalMillis, 100_000, System::currentTimeMillis);
    }

    /** Test seam: injectable bucket cap + clock. */
    public RateLimiter(final long capacity, final long refillTokens, final long refillIntervalMillis,
                       final int maxBuckets, final LongSupplier clock) {
        this.capacity = capacity;
        this.refillTokens = refillTokens;
        this.refillIntervalMillis = refillIntervalMillis;
        this.maxBuckets = maxBuckets;
        this.clock = clock;
    }

    /** Outcome of a rate-limit check. */
    public record Decision(boolean allowed, long retryAfterSeconds) {
    }

    /** Attempts to consume a token for {@code key}; returns allow/deny plus a {@code Retry-After} hint. */
    public Decision check(final String key) {
        final long now = clock.getAsLong();
        if (buckets.size() > maxBuckets) {
            buckets.clear(); // coarse safety valve against unbounded growth (resets every window worst case)
        }
        final Entry entry = buckets.computeIfAbsent(key,
                k -> new Entry(new TokenBucket(capacity, refillTokens, refillIntervalMillis, now)));
        synchronized (entry.bucket) {
            entry.lastTouchMillis = now;
            final boolean allowed = entry.bucket.tryConsume(now);
            return new Decision(allowed, allowed ? 0 : entry.bucket.retryAfterSeconds(now));
        }
    }

    /** Visible for tests. */
    public int bucketCount() {
        return buckets.size();
    }

    private static final class Entry {
        private final TokenBucket bucket;
        private long lastTouchMillis;

        private Entry(final TokenBucket bucket) {
            this.bucket = bucket;
        }
    }
}
