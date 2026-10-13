/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A cap on concurrent {@link PinnedHttpFetcher} fetches, with an optional sub-cap per partition (a realm). A permit is
 * taken before the fetch's worker starts and given back only when the worker ends, not when its caller stops waiting:
 * a fetch stuck in a DNS lookup that cannot be interrupted keeps its permit, so hung lookups can never pile up more
 * than {@link #max()} threads. A caller that gets no permit before its deadline fails with a timeout.
 *
 * <p>Every outbound feature group has its own limiter ({@link #forGroup}), so a slow or hostile target of one group
 * (say a tarpit webhook) can never take the slots of another (an OIDC broker login, an OTP message), and within a group
 * one realm can hold at most {@link #perPartitionMax()} slots, so it cannot starve the other realms. Sizes:
 * {@code helix.outbound.fetch.<group>.max-concurrent} and {@code .per-realm-max} ({@code OutboundFetchLimits}).
 */
public final class FetchLimiter {

    /** The outbound feature groups, each with its own slots. */
    public enum Group {
        /** Wallet status lists and issuer CRL / OCSP. */
        WALLET(16, 16),
        /** Login, admin-configured targets: OIDC broker token + JWKS, eID ArtifactResolve, WIF JWKS and discovery. */
        LOGIN_ADMIN(32, 8),
        /**
         * Login, client-controlled targets (any client registrant, open DCR included): the token endpoint's client
         * assertion JWKS and the FAPI request-object JWKS. Kept apart so registered clients cannot starve broker logins.
         */
        LOGIN_CLIENT(32, 8),
        /** OTP and notification delivery: HTTP email / SMS / push drivers, the Cloudflare email API. */
        OTP(32, 8),
        /** Webhooks, SCIM provisioning, back-channel and upstream logout, admin document fetches. */
        OUTBOUND(32, 8);

        final int defaultMax;
        final int defaultPerPartition;

        Group(final int defaultMax, final int defaultPerPartition) {
            this.defaultMax = defaultMax;
            this.defaultPerPartition = defaultPerPartition;
        }

        public int defaultMax() {
            return defaultMax;
        }

        public int defaultPerRealmMax() {
            return defaultPerPartition;
        }
    }

    /** The wallet group's default size (kept for the old {@code helix.wallet.fetch.max-concurrent}). */
    public static final int DEFAULT_MAX = 16;
    private static final Map<Group, FetchLimiter> GROUPS = new EnumMap<>(Group.class);

    static {
        for (final Group g : Group.values()) {
            GROUPS.put(g, new FetchLimiter(g.defaultMax, g.defaultPerPartition));
        }
    }

    /**
     * A {@link ReentrantLock} and {@link Condition}, never a monitor: a virtual thread that waits in
     * {@code Object.wait} (or blocks entering a {@code synchronized} block) pins its carrier on JDK 21, so enough
     * waiters of one realm would take every carrier and stall every other fetch. Waiting on a {@code Condition}
     * unmounts the virtual thread.
     */
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition changed = lock.newCondition();
    private int max;
    private int perPartitionMax;
    private int inFlight;
    private final Map<String, Integer> byPartition = new HashMap<>();

    public FetchLimiter(final int max) {
        this(max, max);
    }

    public FetchLimiter(final int max, final int perPartitionMax) {
        configure(max, perPartitionMax);
    }

    /** The limiter of a feature group. */
    public static FetchLimiter forGroup(final Group group) {
        return GROUPS.get(group);
    }

    /** The wallet group's limiter (the default of fetchers that are not given one). */
    public static FetchLimiter global() {
        return forGroup(Group.WALLET);
    }

    /** Changes the cap; fetches already running keep their permits. */
    public void setMax(final int value) {
        lock.lock();
        try {
            configure(value, Math.min(perPartitionMax == 0 ? value : perPartitionMax, value));
        } finally {
            lock.unlock();
        }
    }

    /** Changes both caps; {@code perPartition} is clamped to {@code max}. */
    public void configure(final int newMax, final int perPartition) {
        if (newMax < 1 || perPartition < 1) {
            throw new IllegalArgumentException("outbound fetch concurrency caps must be at least 1");
        }
        lock.lock();
        try {
            max = newMax;
            perPartitionMax = Math.min(perPartition, newMax);
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    public int max() {
        lock.lock();
        try {
            return max;
        } finally {
            lock.unlock();
        }
    }

    public int perPartitionMax() {
        lock.lock();
        try {
            return perPartitionMax;
        } finally {
            lock.unlock();
        }
    }

    /** Fetches holding a permit now. */
    public int inFlight() {
        lock.lock();
        try {
            return inFlight;
        } finally {
            lock.unlock();
        }
    }

    /** Fetches of {@code partition} holding a permit now. */
    public int inFlight(final String partition) {
        lock.lock();
        try {
            return byPartition.getOrDefault(partition, 0);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Takes a permit for {@code partition} (null: no sub-cap applies), waiting at most until {@code deadlineNanos}
     * ({@link System#nanoTime()}); false on timeout.
     */
    boolean acquire(final long deadlineNanos, final String partition) throws InterruptedException {
        lock.lockInterruptibly();
        try {
            while (inFlight >= max || partition != null && byPartition.getOrDefault(partition, 0) >= perPartitionMax) {
                final long remaining = deadlineNanos - System.nanoTime();
                if (remaining <= 0) {
                    return false;
                }
                changed.awaitNanos(remaining);
            }
            inFlight++;
            if (partition != null) {
                byPartition.merge(partition, 1, Integer::sum);
            }
            return true;
        } finally {
            lock.unlock();
        }
    }

    boolean acquire(final long deadlineNanos) throws InterruptedException {
        return acquire(deadlineNanos, null);
    }

    void release(final String partition) {
        lock.lock();
        try {
            inFlight--;
            if (partition != null) {
                byPartition.computeIfPresent(partition, (k, v) -> v <= 1 ? null : v - 1);
            }
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    void release() {
        release(null);
    }
}
