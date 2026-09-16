/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.workloadidentity;

import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM WIF: the exchange endpoint is throttled per (realm, source-IP) so a flood of forged tokens
 * can't be used to probe the verifier. A fixed window of {@code MAX} attempts; the window resets after
 * its duration elapses; distinct keys are independent.
 */
class WorkloadExchangeRateLimiterTest {

    @Test
    void allowsUpToTheLimitThenBlocks() {
        final AtomicLong clock = new AtomicLong(0);
        final WorkloadExchangeRateLimiter limiter = new WorkloadExchangeRateLimiter(3, 60_000, clock::get);

        assertThat(limiter.allow("master", "1.1.1.1")).isTrue();
        assertThat(limiter.allow("master", "1.1.1.1")).isTrue();
        assertThat(limiter.allow("master", "1.1.1.1")).isTrue();
        assertThat(limiter.allow("master", "1.1.1.1")).isFalse();
    }

    @Test
    void resetsAfterTheWindowElapses() {
        final AtomicLong clock = new AtomicLong(0);
        final WorkloadExchangeRateLimiter limiter = new WorkloadExchangeRateLimiter(2, 60_000, clock::get);

        assertThat(limiter.allow("master", "1.1.1.1")).isTrue();
        assertThat(limiter.allow("master", "1.1.1.1")).isTrue();
        assertThat(limiter.allow("master", "1.1.1.1")).isFalse();

        clock.set(61_000);
        assertThat(limiter.allow("master", "1.1.1.1")).isTrue();
    }

    @Test
    void keysAreIndependent() {
        final AtomicLong clock = new AtomicLong(0);
        final WorkloadExchangeRateLimiter limiter = new WorkloadExchangeRateLimiter(1, 60_000, clock::get);

        assertThat(limiter.allow("master", "1.1.1.1")).isTrue();
        assertThat(limiter.allow("master", "1.1.1.1")).isFalse();
        assertThat(limiter.allow("master", "2.2.2.2")).isTrue();
        assertThat(limiter.allow("other", "1.1.1.1")).isTrue();
    }
}
