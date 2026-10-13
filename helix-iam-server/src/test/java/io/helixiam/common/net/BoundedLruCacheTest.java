/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/** The JWKS / decoder caches drop the least recently used entry, never everything at once. */
class BoundedLruCacheTest {

    @Test
    void theLeastRecentlyUsedEntryIsEvictedAndHotEntriesStay() {
        final BoundedLruCache<String, Integer> cache = new BoundedLruCache<>(3);
        final AtomicInteger built = new AtomicInteger();
        for (final String k : new String[] {"a", "b", "c"}) {
            cache.computeIfAbsent(k, x -> built.incrementAndGet());
        }
        cache.computeIfAbsent("a", x -> built.incrementAndGet()); // a is hot
        cache.computeIfAbsent("d", x -> built.incrementAndGet()); // evicts b, the least recently used
        assertThat(cache.size()).isEqualTo(3);
        assertThat(cache.contains("a")).isTrue();
        assertThat(cache.contains("b")).isFalse();
        assertThat(cache.contains("c")).isTrue();
        assertThat(built).hasValue(4);
    }

    @Test
    void aFullCacheIsNeverClearedAtOnce() {
        final BoundedLruCache<Integer, Integer> cache = new BoundedLruCache<>(1_000);
        for (int i = 0; i < 5_000; i++) {
            cache.computeIfAbsent(i, x -> x);
            cache.computeIfAbsent(0, x -> -1); // keep 0 hot
        }
        assertThat(cache.size()).isEqualTo(1_000);
        assertThat(cache.contains(0)).isTrue();
        assertThat(cache.contains(4_999)).isTrue();
    }
}
