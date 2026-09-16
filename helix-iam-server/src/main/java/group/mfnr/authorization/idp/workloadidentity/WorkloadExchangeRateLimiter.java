package group.mfnr.authorization.idp.workloadidentity;

import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Helix IAM WIF: a small in-memory fixed-window rate limiter for the token-exchange endpoint, keyed by
 * (realm, source-IP). It bounds how fast a caller can probe the cryptographic verifier with forged
 * tokens. Best-effort and node-local (the verifier is the real security control); intentionally simple.
 */
class WorkloadExchangeRateLimiter {

    private final int max;
    private final long windowMillis;
    private final LongSupplier clock;
    private final ConcurrentHashMap<String, Window> windows = new ConcurrentHashMap<>();

    WorkloadExchangeRateLimiter() {
        this(60, 60_000, System::currentTimeMillis);
    }

    WorkloadExchangeRateLimiter(final int max, final long windowMillis, final LongSupplier clock) {
        this.max = max;
        this.windowMillis = windowMillis;
        this.clock = clock;
    }

    /** True if this (realm, ip) is under the per-window cap; counts the attempt. */
    boolean allow(final String realm, final String sourceIp) {
        final String key = (realm == null ? "-" : realm) + "|" + (sourceIp == null ? "-" : sourceIp);
        final long now = clock.getAsLong();
        final Window w = windows.compute(key, (k, existing) -> {
            if (existing == null || now - existing.start >= windowMillis) {
                return new Window(now, 1);
            }
            existing.count++;
            return existing;
        });
        return w.count <= max;
    }

    private static final class Window {
        private final long start;
        private int count;

        private Window(final long start, final int count) {
            this.start = start;
            this.count = count;
        }
    }
}
