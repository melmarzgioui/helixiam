/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import java.util.concurrent.TimeUnit;

/**
 * A cap on concurrent {@link PinnedHttpFetcher} fetches. A permit is taken before the fetch's worker starts and given
 * back only when the worker ends, not when its caller stops waiting: a fetch stuck in a DNS lookup that cannot be
 * interrupted keeps its permit, so hung lookups can never pile up more than {@link #max()} threads. A caller that
 * gets no permit before its deadline fails with a timeout. {@link #global()} is shared by every fetcher that is not
 * given its own ({@code helix.wallet.fetch.max-concurrent}, default {@value #DEFAULT_MAX}).
 */
public final class FetchLimiter {

    public static final int DEFAULT_MAX = 16;
    private static final FetchLimiter GLOBAL = new FetchLimiter(DEFAULT_MAX);

    private int max;
    private int inFlight;

    public FetchLimiter(final int max) {
        setMax(max);
    }

    /** The limiter shared by every fetcher that is not given its own. */
    public static FetchLimiter global() {
        return GLOBAL;
    }

    /** Changes the cap; fetches already running keep their permits. */
    public synchronized void setMax(final int value) {
        if (value < 1) {
            throw new IllegalArgumentException("the outbound fetch concurrency cap must be at least 1");
        }
        max = value;
        notifyAll();
    }

    public synchronized int max() {
        return max;
    }

    /** Fetches holding a permit now. */
    public synchronized int inFlight() {
        return inFlight;
    }

    /** Takes a permit, waiting at most until {@code deadlineNanos} ({@link System#nanoTime()}); false on timeout. */
    synchronized boolean acquire(final long deadlineNanos) throws InterruptedException {
        while (inFlight >= max) {
            final long remaining = deadlineNanos - System.nanoTime();
            if (remaining <= 0) {
                return false;
            }
            TimeUnit.NANOSECONDS.timedWait(this, remaining);
        }
        inFlight++;
        return true;
    }

    synchronized void release() {
        inFlight--;
        notifyAll();
    }
}
