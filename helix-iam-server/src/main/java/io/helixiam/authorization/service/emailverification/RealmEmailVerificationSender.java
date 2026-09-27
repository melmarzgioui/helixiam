/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.emailverification;

import io.helixiam.authorization.messaging.MessagingService;
import io.helixiam.common.log.LogSafe;
import io.helixiam.notification.Notifier;
import io.helixiam.notification.domain.NotificationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * C3: emails the verification link through the realm's configured email provider (SMTP or HTTP driver), rendering
 * the realm's {@code verify-email} template ({@code {{link}}}, {@code {{ttl}}}, {@code {{realm}}}, {@code {{user}}}).
 * Without a realm provider it falls back to the global notifier (global SMTP, {@code helix.notification.smtp.*}).
 * The link is never written to the log.
 */
@Component
public class RealmEmailVerificationSender implements EmailVerificationSender {

    /** Message-template key of the verification email. */
    public static final String TEMPLATE = "verify-email";
    /** Notification type used on the global-SMTP fallback path. */
    public static final String NOTIFICATION_TYPE = "VERIFY_EMAIL";

    private static final Logger LOG = LogManager.getLogger(RealmEmailVerificationSender.class);

    private final MessagingService messaging;
    private final Notifier notifier;

    public RealmEmailVerificationSender(final MessagingService messaging, final Notifier notifier) {
        this.messaging = messaging;
        this.notifier = notifier;
    }

    @Override
    public boolean send(final EmailVerificationMessage message) {
        try {
            final Map<String, String> vars = new LinkedHashMap<>();
            vars.put("realm", message.realmId());
            vars.put("link", message.link());
            vars.put("ttl", io.helixiam.authorization.messaging.DefaultMessageTemplates.hours(message.ttlHours(), org.springframework.context.i18n.LocaleContextHolder.getLocale()));
            vars.put("user", message.email());
            if (messaging.sendEmail(message.realmId(), message.email(), TEMPLATE, vars)) {
                LOG.info("Verification email sent to user {} in realm {}",
                        LogSafe.sanitize(message.userId()), LogSafe.sanitize(message.realmId()));
                return true;
            }
            final NotificationRequest fallback = new NotificationRequest(NOTIFICATION_TYPE);
            fallback.setEmailAddress(message.email());
            fallback.getAdditionalData().put("link", message.link());
            fallback.getAdditionalData().put("realm", message.realmId());
            fallback.getAdditionalData().put("ttl", message.ttlHours() + " hours");
            fallback.getAdditionalData().put("ttlHours", String.valueOf(message.ttlHours()));
            notifier.sendEmailNotification(fallback); // never throws; logs when no global SMTP is configured
            return true;
        } catch (final RuntimeException e) {
            LOG.warn("Verification email for user {} NOT sent: {}", LogSafe.sanitize(message.userId()),
                    LogSafe.sanitize(e.getMessage()));
            return false;
        }
    }
}
