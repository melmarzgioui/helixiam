/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

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
        /** Login-critical: OIDC broker token + JWKS, eID ArtifactResolve, client and WIF JWKS, issuer discovery. */
        LOGIN(32, 8),
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
    public synchronized void setMax(final int value) {
        configure(value, Math.min(perPartitionMax == 0 ? value : perPartitionMax, value));
    }

    /** Changes both caps; {@code perPartition} is clamped to {@code max}. */
    public synchronized void configure(final int newMax, final int perPartition) {
        if (newMax < 1 || perPartition < 1) {
            throw new IllegalArgumentException("outbound fetch concurrency caps must be at least 1");
        }
        max = newMax;
        perPartitionMax = Math.min(perPartition, newMax);
        notifyAll();
    }

    public synchronized int max() {
        return max;
    }

    public synchronized int perPartitionMax() {
        return perPartitionMax;
    }

    /** Fetches holding a permit now. */
    public synchronized int inFlight() {
        return inFlight;
    }

    /** Fetches of {@code partition} holding a permit now. */
    public synchronized int inFlight(final String partition) {
        return byPartition.getOrDefault(partition, 0);
    }

    /**
     * Takes a permit for {@code partition} (null: no sub-cap applies), waiting at most until {@code deadlineNanos}
     * ({@link System#nanoTime()}); false on timeout.
     */
    synchronized boolean acquire(final long deadlineNanos, final String partition) throws InterruptedException {
        while (inFlight >= max || partition != null && byPartition.getOrDefault(partition, 0) >= perPartitionMax) {
            final long remaining = deadlineNanos - System.nanoTime();
            if (remaining <= 0) {
                return false;
            }
            TimeUnit.NANOSECONDS.timedWait(this, remaining);
        }
        inFlight++;
        if (partition != null) {
            byPartition.merge(partition, 1, Integer::sum);
        }
        return true;
    }

    synchronized boolean acquire(final long deadlineNanos) throws InterruptedException {
        return acquire(deadlineNanos, null);
    }

    synchronized void release(final String partition) {
        inFlight--;
        if (partition != null) {
            byPartition.computeIfPresent(partition, (k, v) -> v <= 1 ? null : v - 1);
        }
        notifyAll();
    }

    synchronized void release() {
        release(null);
    }
}
