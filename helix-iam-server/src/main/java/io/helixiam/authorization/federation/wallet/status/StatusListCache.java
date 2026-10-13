/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.status;

import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * The verified Status List Tokens kept by {@link TokenStatusListClient}, bounded both by entry count and by the total
 * decoded (inflated) list bytes, least recently used evicted first. One instance is shared by every wallet provider
 * ({@code helix.wallet.status-list.cache-max-entries}, default {@value #DEFAULT_MAX_ENTRIES};
 * {@code helix.wallet.status-list.cache-max-bytes}, default 32 MB), so the budget is global: without the byte bound the
 * worst case was {@value #DEFAULT_MAX_ENTRIES} lists of {@value StatusListToken#MAX_INFLATED_BYTES} bytes (128 MB). A
 * list larger than the whole budget is not cached.
 *
 * <p>An entry records when it was fetched, not when it expires: each client computes its own expiry from its own
 * {@code maxCache}, so providers with different policies can share the cache.
 */
public final class StatusListCache {

    public static final int DEFAULT_MAX_ENTRIES = 64;
    public static final long DEFAULT_MAX_BYTES = 32L * 1024 * 1024;

    /** What a cached token was fetched for: the uri, the form and the anchors it was verified against. */
    record Key(String uri, String form, Set<Object> anchors) {
    }

    /** A verified token and when it was fetched. */
    record Entry(StatusListToken token, Instant fetchedAt) {
    }

    private record Sized(Entry entry, long bytes) {
    }

    private final int maxEntries;
    private final long maxBytes;
    private final Map<Key, Sized> entries = new LinkedHashMap<>(16, 0.75f, true);
    private long bytes;

    /** The defaults: {@value #DEFAULT_MAX_ENTRIES} entries, 32 MB. */
    public StatusListCache() {
        this(DEFAULT_MAX_ENTRIES, DEFAULT_MAX_BYTES);
    }

    public StatusListCache(final int maxEntries, final long maxBytes) {
        if (maxEntries < 0 || maxBytes < 0) {
            throw new IllegalArgumentException("helix.wallet.status-list cache limits must not be negative");
        }
        this.maxEntries = maxEntries;
        this.maxBytes = maxBytes;
    }

    synchronized Entry get(final Key key) {
        final Sized s = entries.get(key);
        return s == null ? null : s.entry();
    }

    synchronized void remove(final Key key) {
        final Sized old = entries.remove(key);
        if (old != null) {
            bytes -= old.bytes();
        }
    }

    /** Stores {@code token}, then evicts the least recently used entries until both bounds hold. */
    synchronized void put(final Key key, final StatusListToken token, final Instant fetchedAt) {
        Objects.requireNonNull(token, "token");
        remove(key);
        final long size = token.decodedSize();
        if (maxEntries == 0 || size > maxBytes) {
            return;
        }
        entries.put(key, new Sized(new Entry(token, fetchedAt), size));
        bytes += size;
        final Iterator<Sized> it = entries.values().iterator();
        while ((entries.size() > maxEntries || bytes > maxBytes) && it.hasNext()) {
            bytes -= it.next().bytes();
            it.remove();
        }
    }

    /** Cached lists. */
    public synchronized int entries() {
        return entries.size();
    }

    /** Decoded list bytes held. */
    public synchronized long bytes() {
        return bytes;
    }

    public int maxEntries() {
        return maxEntries;
    }

    public long maxBytes() {
        return maxBytes;
    }
}
