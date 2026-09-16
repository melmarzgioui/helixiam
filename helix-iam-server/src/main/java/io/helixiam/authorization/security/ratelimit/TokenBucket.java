package io.helixiam.authorization.security.ratelimit;

/**
 * Auth-hardening (feature 2): a hand-rolled, dependency-free token bucket (no bucket4j). Refills
 * continuously at {@code refillTokens / refillIntervalMillis} and caps at {@code capacity}. Each accepted
 * request consumes one token; when empty, {@link #tryConsume} returns {@code false} and the caller throttles.
 *
 * <p>Not thread-safe on its own — callers synchronise on the bucket instance (see {@link RateLimiter}). The
 * clock is supplied per call so the bucket is fully unit-testable without sleeping.
 */
public final class TokenBucket {

    private final long capacity;
    private final long refillTokens;
    private final long refillIntervalMillis;

    private double tokens;
    private long lastRefillMillis;

    public TokenBucket(final long capacity, final long refillTokens, final long refillIntervalMillis, final long nowMillis) {
        if (capacity <= 0 || refillTokens <= 0 || refillIntervalMillis <= 0) {
            throw new IllegalArgumentException("capacity, refillTokens and refillIntervalMillis must be positive");
        }
        this.capacity = capacity;
        this.refillTokens = refillTokens;
        this.refillIntervalMillis = refillIntervalMillis;
        this.tokens = capacity;
        this.lastRefillMillis = nowMillis;
    }

    /** Refills based on elapsed time, then consumes one token if available. */
    public boolean tryConsume(final long nowMillis) {
        refill(nowMillis);
        if (tokens >= 1.0d) {
            tokens -= 1.0d;
            return true;
        }
        return false;
    }

    /** Seconds until at least one token is available (rounded up, minimum 1) — for the {@code Retry-After} header. */
    public long retryAfterSeconds(final long nowMillis) {
        refill(nowMillis);
        if (tokens >= 1.0d) {
            return 0;
        }
        final double needed = 1.0d - tokens;
        final double millisPerToken = (double) refillIntervalMillis / (double) refillTokens;
        return Math.max(1L, (long) Math.ceil(needed * millisPerToken / 1000.0d));
    }

    private void refill(final long nowMillis) {
        final long elapsed = nowMillis - lastRefillMillis;
        if (elapsed <= 0) {
            return;
        }
        final double added = (double) elapsed * (double) refillTokens / (double) refillIntervalMillis;
        if (added > 0) {
            tokens = Math.min((double) capacity, tokens + added);
            lastRefillMillis = nowMillis;
        }
    }
}
