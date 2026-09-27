/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.account;

import io.helixiam.authorization.security.ratelimit.RateLimiter;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * B1: per-user limits on the account console's sensitive actions, on top of the realm's account lockout (a wrong
 * password or code in the console also counts toward it). The key is {@code realm|userId}; buckets refill over the
 * window, so a user who hits a limit can try again a few minutes later.
 */
@Component
public class AccountRateLimits {

    /** A limited action: attempts allowed per window. */
    public enum Action {
        /** Changing the password (each attempt, right or wrong). */
        PASSWORD(10, 15),
        /** Re-authentication before a sensitive action. */
        STEP_UP(10, 15),
        /** Confirming a new authenticator app, or new recovery codes, with a code. */
        CODE(10, 15),
        /** Sending an email-confirmation link. */
        EMAIL(5, 60),
        /** Downloading the data. */
        EXPORT(10, 60);

        final int attempts;
        final long windowMinutes;

        Action(final int attempts, final long windowMinutes) {
            this.attempts = attempts;
            this.windowMinutes = windowMinutes;
        }
    }

    private final Map<Action, RateLimiter> limiters = new EnumMap<>(Action.class);

    public AccountRateLimits() {
        for (final Action a : Action.values()) {
            limiters.put(a, new RateLimiter(a.attempts, a.attempts, TimeUnit.MINUTES.toMillis(a.windowMinutes)));
        }
    }

    /** Takes one attempt of {@code action} for the user; false when the limit is reached. */
    public boolean allow(final Action action, final String realm, final String userId) {
        return limiters.get(action).check(realm + "|" + userId).allowed();
    }
}
