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
 * blocked, and one realm with a slow or hostile endpoint cannot pile up unbounded work or memory. On top of that, at
 * most {@link #maxPendingTotal()} are pending across all realms (default {@value #DEFAULT_MAX_PENDING_TOTAL},
 * {@code helix.outbound.deliveries.max-pending}), so many realms together cannot either; past it, deliveries are
 * dropped and counted the same way ({@link #droppedTotal}).
 */
public final class RealmBoundedExecutor {

    public static final int DEFAULT_MAX_PENDING_PER_REALM = 1_000;
    public static final int DEFAULT_MAX_PENDING_TOTAL = 20_000;
    private static final Logger LOG = LogManager.getLogger(RealmBoundedExecutor.class);
    private static final long LOG_INTERVAL_NANOS = 60_000_000_000L;
    private static final String NO_REALM = "(no realm)";

    private final String name;
    private final int maxPendingPerRealm;
    private final ExecutorService executor;
    private final Map<String, AtomicInteger> pending = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> dropped = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> lastLogged = new ConcurrentHashMap<>();
    private final AtomicInteger pendingTotal = new AtomicInteger();
    private final AtomicLong droppedTotal = new AtomicLong();
    private final AtomicLong lastTotalLogged = new AtomicLong(System.nanoTime() - LOG_INTERVAL_NANOS);
    private volatile int maxPendingTotal;

    public RealmBoundedExecutor(final String name, final int maxPendingPerRealm) {
        this(name, maxPendingPerRealm, DEFAULT_MAX_PENDING_TOTAL);
    }

    public RealmBoundedExecutor(final String name, final int maxPendingPerRealm, final int maxPendingTotal) {
        if (maxPendingPerRealm < 1) {
            throw new IllegalArgumentException("maxPendingPerRealm must be at least 1");
        }
        this.name = Objects.requireNonNull(name, "name");
        this.maxPendingPerRealm = maxPendingPerRealm;
        setMaxPendingTotal(maxPendingTotal);
        this.executor = Executors.newThreadPerTaskExecutor(Thread.ofVirtual().name(name + "-", 0).factory());
    }

    public int maxPendingPerRealm() {
        return maxPendingPerRealm;
    }

    public int maxPendingTotal() {
        return maxPendingTotal;
    }

    /** The ceiling across all realms (at least 1). */
    public void setMaxPendingTotal(final int value) {
        if (value < 1) {
            throw new IllegalArgumentException("maxPendingTotal must be at least 1");
        }
        this.maxPendingTotal = value;
    }

    /** Deliveries queued or running now, all realms together. */
    public int pendingTotal() {
        return pendingTotal.get();
    }

    /** Deliveries dropped so far, for any reason (realm bound or the global ceiling). */
    public long droppedTotal() {
        return droppedTotal.get();
    }

    /** Runs {@code task} for {@code realm}, or drops it (false) when the realm already has the maximum pending. */
    public boolean submit(final String realm, final Runnable task) {
        final String key = realm == null || realm.isBlank() ? NO_REALM : realm;
        final AtomicInteger count = pending.computeIfAbsent(key, k -> new AtomicInteger());
        if (pendingTotal.incrementAndGet() > maxPendingTotal) {
            pendingTotal.decrementAndGet();
            final long total = droppedTotal.incrementAndGet();
            dropped.computeIfAbsent(key, k -> new AtomicLong()).incrementAndGet();
            final long now = System.nanoTime();
            final long seen = lastTotalLogged.get();
            if (now - seen >= LOG_INTERVAL_NANOS && lastTotalLogged.compareAndSet(seen, now)) {
                LOG.warn("{}: {} deliveries pending across all realms; dropping new ones ({} dropped so far)", name,
                        maxPendingTotal, total);
            }
            return false;
        }
        if (count.incrementAndGet() > maxPendingPerRealm) {
            count.decrementAndGet();
            pendingTotal.decrementAndGet();
            droppedTotal.incrementAndGet();
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
                    pendingTotal.decrementAndGet();
                }
            });
            return true;
        } catch (final RuntimeException e) {
            count.decrementAndGet();
            pendingTotal.decrementAndGet();
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
