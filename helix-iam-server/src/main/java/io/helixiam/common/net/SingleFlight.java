/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import java.time.Duration;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Collapses concurrent calls for the same key into one: the first caller runs the call, the others wait for its result
 * (or its exception) for at most their own timeout. Once the call ends the key is free again; nothing is cached here.
 * Used so that many logins needing the same CRL, OCSP response or status list fetch it once.
 *
 * @param <K> the key (a URL and whatever else makes the answer differ)
 * @param <V> the result
 */
public final class SingleFlight<K, V> {

    /** A follower stopped waiting at its own deadline. */
    public static final class WaitTimeoutException extends Exception {
        WaitTimeoutException() {
            super("timed out waiting for a shared fetch", null, false, false);
        }
    }

    private final ConcurrentMap<K, CompletableFuture<V>> inFlight = new ConcurrentHashMap<>();

    /**
     * Runs {@code call} for {@code key}, or waits (at most {@code wait}) for the run already in flight.
     *
     * @throws WaitTimeoutException a follower's wait ended before the shared call did
     * @throws Exception            whatever the shared call threw
     */
    public V run(final K key, final Duration wait, final Callable<V> call) throws Exception {
        final CompletableFuture<V> mine = new CompletableFuture<>();
        final CompletableFuture<V> existing = inFlight.putIfAbsent(key, mine);
        if (existing != null) {
            try {
                return existing.get(Math.max(1, wait.toNanos()), TimeUnit.NANOSECONDS);
            } catch (final TimeoutException e) {
                throw new WaitTimeoutException();
            } catch (final ExecutionException e) {
                throw e.getCause() instanceof Exception cause ? cause : e;
            }
        }
        try {
            final V value = call.call();
            mine.complete(value);
            return value;
        } catch (final Exception | Error e) {
            mine.completeExceptionally(e);
            throw e;
        } finally {
            inFlight.remove(key, mine);
        }
    }
}
