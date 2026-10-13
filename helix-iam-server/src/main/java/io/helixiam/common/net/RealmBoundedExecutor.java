/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Background outbound deliveries (webhooks, SCIM provisioning), each on a virtual thread, with at most
 * {@link #maxPendingPerRealm()} pending (queued or running) per realm. A delivery over that bound is dropped at once,
 * counted ({@link #dropped}) and logged (once a minute per realm): the producer (a login, an admin write) is never
 * blocked, and one realm with a slow or hostile endpoint cannot pile up unbounded work or memory.
 */
public final class RealmBoundedExecutor {

    public static final int DEFAULT_MAX_PENDING_PER_REALM = 1_000;
    private static final Logger LOG = LogManager.getLogger(RealmBoundedExecutor.class);
    private static final long LOG_INTERVAL_NANOS = 60_000_000_000L;
    private static final String NO_REALM = "(no realm)";

    private final String name;
    private final int maxPendingPerRealm;
    private final ExecutorService executor;
    private final Map<String, AtomicInteger> pending = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> dropped = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> lastLogged = new ConcurrentHashMap<>();

    public RealmBoundedExecutor(final String name, final int maxPendingPerRealm) {
        if (maxPendingPerRealm < 1) {
            throw new IllegalArgumentException("maxPendingPerRealm must be at least 1");
        }
        this.name = Objects.requireNonNull(name, "name");
        this.maxPendingPerRealm = maxPendingPerRealm;
        this.executor = Executors.newThreadPerTaskExecutor(Thread.ofVirtual().name(name + "-", 0).factory());
    }

    public int maxPendingPerRealm() {
        return maxPendingPerRealm;
    }

    /** Runs {@code task} for {@code realm}, or drops it (false) when the realm already has the maximum pending. */
    public boolean submit(final String realm, final Runnable task) {
        final String key = realm == null || realm.isBlank() ? NO_REALM : realm;
        final AtomicInteger count = pending.computeIfAbsent(key, k -> new AtomicInteger());
        if (count.incrementAndGet() > maxPendingPerRealm) {
            count.decrementAndGet();
            final long total = dropped.computeIfAbsent(key, k -> new AtomicLong()).incrementAndGet();
            final AtomicLong last = lastLogged.computeIfAbsent(key, k -> new AtomicLong(System.nanoTime()
                    - LOG_INTERVAL_NANOS));
            final long now = System.nanoTime();
            final long seen = last.get();
            if (now - seen >= LOG_INTERVAL_NANOS && last.compareAndSet(seen, now)) {
                LOG.warn("{}: realm {} has {} deliveries pending; dropping new ones ({} dropped so far)", name,
                        LogSafe.sanitize(key), maxPendingPerRealm, total);
            }
            return false;
        }
        try {
            executor.submit(() -> {
                try {
                    task.run();
                } finally {
                    count.decrementAndGet();
                }
            });
            return true;
        } catch (final RuntimeException e) {
            count.decrementAndGet();
            return false;
        }
    }

    /** Deliveries of {@code realm} queued or running now. */
    public int pending(final String realm) {
        final AtomicInteger c = pending.get(realm);
        return c == null ? 0 : c.get();
    }

    /** Deliveries of {@code realm} dropped so far (a metric). */
    public long dropped(final String realm) {
        final AtomicLong c = dropped.get(realm);
        return c == null ? 0 : c.get();
    }
}
