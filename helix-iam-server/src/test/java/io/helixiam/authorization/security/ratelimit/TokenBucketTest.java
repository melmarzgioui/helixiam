package io.helixiam.authorization.security.ratelimit;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Auth-hardening (feature 2): the hand-rolled token bucket (no bucket4j). */
class TokenBucketTest {

    @Test
    void allowsUpToCapacity_thenThrottles() {
        final TokenBucket bucket = new TokenBucket(3, 3, 60_000, 0L);
        assertThat(bucket.tryConsume(0)).isTrue();
        assertThat(bucket.tryConsume(0)).isTrue();
        assertThat(bucket.tryConsume(0)).isTrue();
        assertThat(bucket.tryConsume(0)).isFalse(); // empty
    }

    @Test
    void refillsOverTime() {
        final TokenBucket bucket = new TokenBucket(2, 2, 1_000, 0L); // 2 tokens / second
        assertThat(bucket.tryConsume(0)).isTrue();
        assertThat(bucket.tryConsume(0)).isTrue();
        assertThat(bucket.tryConsume(0)).isFalse();
        // After 500ms, 1 token refilled (2 tokens/s).
        assertThat(bucket.tryConsume(500)).isTrue();
        assertThat(bucket.tryConsume(500)).isFalse();
    }

    @Test
    void capsAtCapacity_evenAfterLongIdle() {
        final TokenBucket bucket = new TokenBucket(5, 5, 1_000, 0L);
        for (int i = 0; i < 5; i++) {
            bucket.tryConsume(0);
        }
        // Idle 1 hour → refill is capped at capacity (5), not unbounded.
        int allowed = 0;
        for (int i = 0; i < 100; i++) {
            if (bucket.tryConsume(3_600_000)) {
                allowed++;
            }
        }
        assertThat(allowed).isEqualTo(5);
    }

    @Test
    void retryAfter_isPositiveWhenEmpty_andZeroWhenAvailable() {
        final TokenBucket bucket = new TokenBucket(1, 1, 1_000, 0L);
        assertThat(bucket.retryAfterSeconds(0)).isZero();
        bucket.tryConsume(0);
        assertThat(bucket.retryAfterSeconds(0)).isGreaterThanOrEqualTo(1);
    }

    @Test
    void rejectsInvalidConfig() {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> new TokenBucket(0, 1, 1, 0));
    }
}
