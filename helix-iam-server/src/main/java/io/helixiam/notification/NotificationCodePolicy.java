/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.notification;

import io.helixiam.notification.domain.NotificationCode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

/**
 * How long an emailed one-time code works ({@code notification_code}): the password-reset code
 * ({@code helix.notification.reset-password.code-ttl}, default 1 hour) and the sign-up verification code
 * ({@code helix.notification.signup.code-ttl}, default 24 hours). Both are single-use. The email that carries a code
 * gets the same instant as its {@code expiresAt}, so it is never retried after the code stopped working.
 *
 * <p>A code issued before expiries were stored (no {@code expires_at}) expires its TTL after its creation date; one
 * with neither date is expired.
 */
@Component
public class NotificationCodePolicy {

    public static final String RESET_PASSWORD = "USER_RESET_PASSWORD";
    public static final String SIGNUP = "USER_SIGNUP";

    private final Duration resetTtl;
    private final Duration signupTtl;

    public NotificationCodePolicy(@Value("${helix.notification.reset-password.code-ttl:1h}") final Duration resetTtl,
                                  @Value("${helix.notification.signup.code-ttl:24h}") final Duration signupTtl) {
        this.resetTtl = positive(resetTtl, Duration.ofHours(1));
        this.signupTtl = positive(signupTtl, Duration.ofHours(24));
    }

    /** The defaults (1 hour for a reset code, 24 hours for a sign-up code). */
    public static NotificationCodePolicy defaults() {
        return new NotificationCodePolicy(null, null);
    }

    /** How long a code of {@code type} works; null for a type without an expiry. */
    public Duration ttl(final String type) {
        if (RESET_PASSWORD.equals(type)) {
            return resetTtl;
        }
        if (SIGNUP.equals(type)) {
            return signupTtl;
        }
        return null;
    }

    /** A new code's expiry, issued at {@code now}; null for a type without one. */
    public Date expiryFor(final String type, final Instant now) {
        final Duration ttl = ttl(type);
        return ttl == null ? null : Date.from(now.plus(ttl));
    }

    /** When {@code code} stops working; null when its type has no expiry. */
    public Instant expiresAt(final NotificationCode code) {
        if (code.getExpiresAt() != null) {
            return code.getExpiresAt().toInstant();
        }
        final Duration ttl = ttl(code.getType());
        if (ttl == null) {
            return null;
        }
        return code.getCreationDate() == null ? Instant.EPOCH : code.getCreationDate().toInstant().plus(ttl);
    }

    /** True while {@code code} works at {@code now}. */
    public boolean isValid(final NotificationCode code, final Instant now) {
        final Instant expiresAt = expiresAt(code);
        return expiresAt == null || now.isBefore(expiresAt);
    }

    private static Duration positive(final Duration value, final Duration fallback) {
        return value == null || value.isZero() || value.isNegative() ? fallback : value;
    }
}
