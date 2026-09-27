/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.account;

import io.helixiam.authorization.security.session.AuthTimeStamper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.function.LongSupplier;

/**
 * B1: {@code max_age}-style step-up for the account console. A sensitive action (a new authenticator, removing it,
 * changing the email address, downloading or deleting the account) is allowed only when the session's
 * {@code auth_time} — the last interactive sign-in, the same value OIDC {@code max_age} and the ID token's
 * {@code auth_time} use — is at most {@code helix.account.step-up-max-age-seconds} (default 300, 30–3600) old.
 * Otherwise the console asks for the password (and the authenticator code, when one is set up) again, which stamps a
 * new {@code auth_time}.
 */
@Component
public class AccountStepUp {

    static final int MIN_SECONDS = 30;
    static final int MAX_SECONDS = 3600;

    private final long maxAgeSeconds;
    private final LongSupplier nowEpochSeconds;

    @Autowired
    public AccountStepUp(@Value("${helix.account.step-up-max-age-seconds:300}") final long maxAgeSeconds) {
        this(maxAgeSeconds, () -> Instant.now().getEpochSecond());
    }

    AccountStepUp(final long maxAgeSeconds, final LongSupplier nowEpochSeconds) {
        this.maxAgeSeconds = Math.max(MIN_SECONDS, Math.min(MAX_SECONDS, maxAgeSeconds));
        this.nowEpochSeconds = nowEpochSeconds;
    }

    public long maxAgeSeconds() {
        return maxAgeSeconds;
    }

    /** True when this browser session signed in (or re-authenticated) within the step-up window. */
    public boolean fresh(final HttpServletRequest request) {
        final Long authTime = new AuthTimeStamper().read(request);
        if (authTime == null) {
            return false;
        }
        final long age = nowEpochSeconds.getAsLong() - authTime;
        return age >= -5 && age <= maxAgeSeconds;
    }
}
