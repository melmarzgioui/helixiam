/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/** The per-group limiters and their per-realm sub-caps. */
class FetchLimiterTest {

    private static long soon() {
        return System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(50);
    }

    @Test
    void aPartitionCannotTakeMoreThanItsShare() throws Exception {
        final FetchLimiter limiter = new FetchLimiter(4, 2);
        assertThat(limiter.acquire(soon(), "a")).isTrue();
        assertThat(limiter.acquire(soon(), "a")).isTrue();
        assertThat(limiter.acquire(soon(), "a")).isFalse();
        assertThat(limiter.acquire(soon(), "b")).isTrue();
        assertThat(limiter.acquire(soon(), "b")).isTrue();
        assertThat(limiter.acquire(soon(), "c")).isFalse(); // the group cap
        limiter.release("a");
        assertThat(limiter.inFlight("a")).isEqualTo(1);
        assertThat(limiter.acquire(soon(), "c")).isTrue();
    }

    @Test
    void everyGroupHasItsOwnLimiter() {
        assertThat(FetchLimiter.forGroup(FetchLimiter.Group.WALLET))
                .isNotSameAs(FetchLimiter.forGroup(FetchLimiter.Group.LOGIN_ADMIN))
                .isSameAs(FetchLimiter.global());
        assertThat(FetchLimiter.forGroup(FetchLimiter.Group.OUTBOUND).perPartitionMax())
                .isLessThan(FetchLimiter.forGroup(FetchLimiter.Group.OUTBOUND).max());
    }
}
