/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import io.helixiam.authorization.security.ratelimit.TokenBucket;

import java.time.Clock;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The send rate caps: at most {@code realm-per-minute} emails per realm (or the realm's own
 * {@code sendLimitPerMinute}) and {@code global-per-minute} for the whole server, each a token bucket that refills
 * over a minute. They protect the provider's quota from a flood of password-reset or sign-in requests, on top of the
 * per-user and per-IP request limits. Counted in memory, per replica. A limit of {@code 0} or less is no cap.
 */
public class EmailSendRateCap {

    /** Which cap refused an email. */
    public enum Scope { REALM, GLOBAL }

    /** The decision for one email: allowed, or refused by {@code scope} with its {@code limitPerMinute}. */
    public record Decision(boolean allowed, Scope scope, int limitPerMinute) {

        static final Decision ALLOWED = new Decision(true, null, 0);
    }

    private static final long MINUTE_MILLIS = 60_000L;
    private static final int MAX_REALMS = 10_000;
    private static final String NO_REALM = "\u0000(none)";

    private final EmailProperties.RateLimit limits;
    private final Clock clock;
    private final ConcurrentHashMap<String, Bucket> realms = new ConcurrentHashMap<>();
    private volatile Bucket global;

    public EmailSendRateCap(final EmailProperties.RateLimit limits, final Clock clock) {
        this.limits = limits == null ? new EmailProperties.RateLimit() : limits;
        this.clock = clock == null ? Clock.systemUTC() : clock;
    }

    /**
     * Takes one email from the realm's and the server's budget. {@code realmLimit} is the realm's own limit (null: the
     * default).
     */
    public Decision tryAcquire(final String realm, final Integer realmLimit) {
        final long now = clock.millis();
        final int perRealm = realmLimit != null ? realmLimit : limits.getRealmPerMinute();
        if (perRealm > 0) {
            if (realms.size() > MAX_REALMS) {
                realms.clear();
            }
            final Bucket bucket = realms.compute(realm == null ? NO_REALM : realm,
                    (k, b) -> b == null || b.limit != perRealm ? new Bucket(perRealm, now) : b);
            if (!bucket.tryConsume(now)) {
                return new Decision(false, Scope.REALM, perRealm);
            }
        }
        final int perServer = limits.getGlobalPerMinute();
        if (perServer > 0) {
            Bucket g = global;
            if (g == null || g.limit != perServer) {
                synchronized (this) {
                    g = global;
                    if (g == null || g.limit != perServer) {
                        g = new Bucket(perServer, now);
                        global = g;
                    }
                }
            }
            if (!g.tryConsume(now)) {
                return new Decision(false, Scope.GLOBAL, perServer);
            }
        }
        return Decision.ALLOWED;
    }

    private static final class Bucket {
        private final int limit;
        private final TokenBucket tokens;

        Bucket(final int limit, final long now) {
            this.limit = limit;
            this.tokens = new TokenBucket(limit, limit, MINUTE_MILLIS, now);
        }

        synchronized boolean tryConsume(final long now) {
            return tokens.tryConsume(now);
        }
    }
}
