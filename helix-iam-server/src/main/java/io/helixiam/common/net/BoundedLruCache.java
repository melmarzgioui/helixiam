/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;

/**
 * A small thread-safe cache of at most {@code maxEntries}, least recently used evicted first (never cleared all at
 * once, so the hot entries stay). Guarded by a {@link ReentrantLock}, not a monitor, because callers may run on virtual
 * threads. Used for the per-URL JWK sources and per-client assertion decoders, whose building does no I/O.
 *
 * @param <K> the key
 * @param <V> the value
 */
public final class BoundedLruCache<K, V> {

    private final ReentrantLock lock = new ReentrantLock();
    private final Map<K, V> entries;

    public BoundedLruCache(final int maxEntries) {
        if (maxEntries < 1) {
            throw new IllegalArgumentException("maxEntries must be at least 1");
        }
        this.entries = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(final Map.Entry<K, V> eldest) {
                return size() > maxEntries;
            }
        };
    }

    /** The cached value of {@code key}, built by {@code build} (without I/O) and cached when absent. */
    public V computeIfAbsent(final K key, final Function<? super K, ? extends V> build) {
        lock.lock();
        try {
            return entries.computeIfAbsent(key, build);
        } finally {
            lock.unlock();
        }
    }

    public boolean contains(final K key) {
        lock.lock();
        try {
            return entries.containsKey(key);
        } finally {
            lock.unlock();
        }
    }

    public int size() {
        lock.lock();
        try {
            return entries.size();
        } finally {
            lock.unlock();
        }
    }
}
