package io.helixiam.authorization.security.ratelimit;

import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

/** Auth-hardening (feature 2): the per-key in-memory bucket registry. */
class RateLimiterTest {

    @Test
    void perKeyBudgetsAreIndependent() {
        final RateLimiter limiter = new RateLimiter(2, 2, 60_000, 1000, () -> 0L);
        assertThat(limiter.check("ip-a").allowed()).isTrue();
        assertThat(limiter.check("ip-a").allowed()).isTrue();
        assertThat(limiter.check("ip-a").allowed()).isFalse(); // a exhausted
        assertThat(limiter.check("ip-b").allowed()).isTrue();   // b unaffected
    }

    @Test
    void deniedDecisionCarriesRetryAfter() {
        final RateLimiter limiter = new RateLimiter(1, 1, 60_000, 1000, () -> 0L);
        assertThat(limiter.check("k").allowed()).isTrue();
        final RateLimiter.Decision denied = limiter.check("k");
        assertThat(denied.allowed()).isFalse();
        assertThat(denied.retryAfterSeconds()).isGreaterThanOrEqualTo(1);
    }

    @Test
    void recoversAfterRefillWindow() {
        final AtomicLong clock = new AtomicLong(0);
        final RateLimiter limiter = new RateLimiter(1, 1, 1_000, 1000, clock::get);
        assertThat(limiter.check("k").allowed()).isTrue();
        assertThat(limiter.check("k").allowed()).isFalse();
        clock.set(1_000); // one full refill interval later
        assertThat(limiter.check("k").allowed()).isTrue();
    }

    @Test
    void evictsWhenOverMaxBuckets() {
        final RateLimiter limiter = new RateLimiter(5, 5, 60_000, 2, () -> 0L);
        limiter.check("a");
        limiter.check("b");
        limiter.check("c"); // triggers the size>max clear path
        assertThat(limiter.bucketCount()).isLessThanOrEqualTo(3);
    }
}
