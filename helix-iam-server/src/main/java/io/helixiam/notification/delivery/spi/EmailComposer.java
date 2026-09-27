/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.notification.delivery.spi;

import io.helixiam.notification.domain.NotificationRequest;

import java.util.Optional;

/**
 * Extension point for the subject and body of an email notification sent by
 * {@link io.helixiam.notification.delivery.SmtpNotifier}. An implementation that returns a message for a notification
 * type (e.g. the realm-branded, localised verification and password-reset emails of
 * {@code io.helixiam.authorization.messaging.AccountEmails}) replaces the plain-text fallback of
 * {@code io.helixiam.notification.delivery.NotificationMessageComposer} for that notification; empty means "use the
 * fallback". Implementations must not throw.
 */
public interface EmailComposer {

    Optional<ComposedEmail> compose(NotificationRequest notification);

    /**
     * One rendered email: subject, body, whether the body is HTML, and the plain-text part (for an HTML body, its text
     * alternative with every link and code; null lets the driver derive it from the HTML).
     */
    record ComposedEmail(String subject, String body, boolean html, String text) {

        public ComposedEmail(final String subject, final String body, final boolean html) {
            this(subject, body, html, html ? null : body);
        }
    }
}
