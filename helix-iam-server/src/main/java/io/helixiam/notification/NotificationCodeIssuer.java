/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.notification;

import io.helixiam.notification.domain.NotificationCode;
import io.helixiam.notification.repository.NotificationCodeRepository;
import io.helixiam.notification.utils.CodeGeneration;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Date;

/**
 * Issues an emailed one-time code (password reset, sign-up verification): a new random code on every call, replacing
 * the account's pending one of the same type. Only its SHA-256 and expiry are stored ({@link NotificationCodePolicy});
 * the returned {@link NotificationCode} carries the plain code for the email and is never persisted.
 */
@Component
public class NotificationCodeIssuer {

    private final NotificationCodeRepository repository;
    private final NotificationCodePolicy policy;

    public NotificationCodeIssuer(final NotificationCodeRepository repository, final NotificationCodePolicy policy) {
        this.repository = repository;
        this.policy = policy == null ? NotificationCodePolicy.defaults() : policy;
    }

    /** A new code of {@code type} for {@code identifier} (a user id); {@code simple} for the short numeric form. */
    public NotificationCode issue(final String identifier, final String type, final boolean simple) {
        final Instant now = Instant.now();
        repository.findByIdentifierAndType(identifier, type).ifPresent(repository::delete);
        final String plain = simple ? CodeGeneration.generateSimpleCode() : CodeGeneration.generateCode();
        final Date expiresAt = policy.expiryFor(type, now);
        final NotificationCode stored = new NotificationCode(identifier, NotificationCodePolicy.hash(plain), type);
        stored.setExpiresAt(expiresAt);
        repository.save(stored);
        final NotificationCode forEmail = new NotificationCode(identifier, plain, type);
        forEmail.setExpiresAt(expiresAt);
        return forEmail;
    }
}
