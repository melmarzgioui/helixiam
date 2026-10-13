/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import java.time.Duration;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Runs blocking outbound work that is not HTTP (an LDAP bind sequence) under a {@link FetchLimiter} group's
 * per-realm slots and one total deadline. The work runs on a virtual thread; the caller waits for a slot and then for
 * the result, both until the deadline. At the deadline the caller gets a {@link TimeoutException} and {@code abort}
 * runs (close the sockets, so the work fails fast). The slot is released when the work itself ends.
 */
public final class BoundedCall {

    private static final ExecutorService WORKERS = Executors.newThreadPerTaskExecutor(
            Thread.ofVirtual().name("bounded-call-", 0).factory());

    private BoundedCall() {
    }

    /**
     * @param group     the limiter group
     * @param realm     the partition; blank means {@link PinnedHttpFetcher#NO_REALM}
     * @param total     the deadline for slot, work and everything inside it (DNS included)
     * @param work      the blocking work
     * @param abort     run at the deadline (may be null)
     * @throws TimeoutException     no slot, or no result, before the deadline
     * @throws ExecutionException   the work failed
     */
    public static <T> T call(final FetchLimiter.Group group, final String realm, final Duration total,
            final Callable<T> work, final Runnable abort) throws TimeoutException, ExecutionException,
            InterruptedException {
        final long deadline = System.nanoTime() + total.toNanos();
        final String partition = realm == null || realm.isBlank() ? PinnedHttpFetcher.NO_REALM : realm;
        final FetchLimiter limiter = FetchLimiter.forGroup(group);
        if (!limiter.acquire(deadline, partition)) {
            throw new TimeoutException("No " + group + " slot before the deadline");
        }
        final Future<T> future;
        try {
            future = WORKERS.submit(() -> {
                try {
                    return work.call();
                } finally {
                    limiter.release(partition);
                }
            });
        } catch (final RuntimeException e) {
            limiter.release(partition);
            throw e;
        }
        try {
            return future.get(Math.max(1, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
        } catch (final TimeoutException e) {
            if (abort != null) {
                abort.run();
            }
            future.cancel(true);
            throw e;
        }
    }
}
