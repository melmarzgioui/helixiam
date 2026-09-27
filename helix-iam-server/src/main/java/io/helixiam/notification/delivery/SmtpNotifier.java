/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.notification.delivery;

import io.helixiam.authorization.messaging.email.CloudflareProperties;
import io.helixiam.authorization.messaging.email.DeliveryResult;
import io.helixiam.authorization.messaging.email.EmailDelivery;
import io.helixiam.authorization.messaging.email.EmailMessage;
import io.helixiam.authorization.messaging.email.EmailOutbox;
import io.helixiam.authorization.messaging.email.EmailSendOutcome;
import io.helixiam.authorization.messaging.email.EmailProperties;
import io.helixiam.authorization.messaging.email.EmailTransport;
import io.helixiam.authorization.messaging.email.GlobalEmailProvider;
import io.helixiam.authorization.repository.messaging.MessagingProviderRepository;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.notification.NotificationConstant;
import io.helixiam.notification.Notifier;
import io.helixiam.notification.delivery.spi.AppSender;
import io.helixiam.notification.delivery.spi.EmailComposer;
import io.helixiam.notification.delivery.spi.SmsSender;
import io.helixiam.notification.domain.NotificationRequest;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Task 4 (strip-RabbitMQ notification delivery). Real {@link Notifier}: EMAIL goes out over SMTP (or
 * whatever email provider the in-flight realm has configured), SMS/APP delegate to their own
 * pluggable {@link SmsSender}/{@link AppSender} SPI. Replaces {@code LoggingNotifier} as the default
 * (see {@code NotificationDeliveryConfig}) but never throws out of any {@code send*} method — a
 * downed mail server must not fail the signup/reset-password request that triggered the notification
 * (mirrors the "log and move on" contract {@code LoggingNotifier} already had), and separately sidesteps
 * a latent bug in {@code io.helixiam.notification.aop.NotificationAspect}'s catch block, which calls
 * {@code exception.getCause().getMessage()} and would NPE on a causeless exception.
 *
 * <h2>Per-realm vs. global SMTP</h2>
 * Email delivery prefers the realm's own configured provider — {@code MessagingProvider} rows entered
 * via Realm Settings &gt; Messaging &gt; Providers, the same store
 * {@code io.helixiam.authorization.messaging.MessagingService} reads for the OTP email
 * senders — dispatched by {@link EmailDelivery} through whichever {@code EmailTransport} (SMTP, CLOUDFLARE, HTTP,
 * LOG) matches that provider's {@code driver} id. Falls back to the global default
 * ({@code helix.notification.email.driver}, {@code helix.notification.smtp.*} / {@code helix.notification.cloudflare.*})
 * only when the realm has none enabled (or there is no realm in
 * context, e.g. for the platform-level {@code USER_SIGNUP}/{@code USER_RESET_PASSWORD} notifications
 * fired from the default/master realm's public signup and reset-password endpoints). When neither is
 * configured, the notification is logged and dropped — never an exception, never a hang.
 */
public class SmtpNotifier implements Notifier {

    private static final Logger LOG = LogManager.getLogger(NotificationConstant.MODULE_NAME);
    private static final String EMAIL_CHANNEL = "EMAIL";

    /**
     * How long a password-reset email is worth sending: the reset code has no server-side expiry, so a reset email
     * is not retried later than this after it was requested.
     */
    static final Duration RESET_EMAIL_VALID_FOR = Duration.ofHours(1);

    private final EmailOutbox outbox;
    private final SmsSender smsSender;
    private final AppSender appSender;
    private final EmailComposer emailComposer;

    /**
     * A notifier over {@code emailTransports}, the realm providers of {@code providerRepository} and the global SMTP of
     * {@code smtpProperties} (tests and simple wiring).
     */
    public SmtpNotifier(final List<? extends EmailTransport> emailTransports,
                        final MessagingProviderRepository providerRepository,
                        final SmsSender smsSender, final AppSender appSender, final SmtpProperties smtpProperties) {
        this(new EmailDelivery(realm -> providerRepository.findByRealmIdAndChannel(realm, EMAIL_CHANNEL).stream()
                        .filter(p -> Boolean.TRUE.equals(p.getEnabled()))
                        .map(MessagingProviderMapper::toResolvedProviderDto).toList(),
                        emailTransports, new GlobalEmailProvider(new EmailProperties(), smtpProperties,
                        new CloudflareProperties()), null, null),
                smsSender, appSender, null);
    }

    /**
     * @param emailComposer renders the emails it knows (realm-branded, localised verification and reset emails);
     *                      null or an empty result falls back to {@link NotificationMessageComposer}'s plain text
     */
    public SmtpNotifier(final EmailDelivery emailDelivery, final SmsSender smsSender, final AppSender appSender,
                        final EmailComposer emailComposer) {
        this(EmailOutbox.direct(emailDelivery), smsSender, appSender, emailComposer);
    }

    /**
     * @param outbox sends the email: the send rate caps, retries of transient failures and bounce marking
     */
    public SmtpNotifier(final EmailOutbox outbox, final SmsSender smsSender, final AppSender appSender,
                        final EmailComposer emailComposer) {
        this.outbox = outbox;
        this.smsSender = smsSender;
        this.appSender = appSender;
        this.emailComposer = emailComposer;
    }

    @Override
    public void sendEmailNotification(final NotificationRequest notification) {
        final String to = notification.getEmailAddress();
        if (to == null || to.isBlank()) {
            LOG.warn("EMAIL notification (type={}) has no recipient address; dropping", notification.getType());
            return;
        }

        final EmailComposer.ComposedEmail composed = composeEmail(notification);
        try {
            final Duration validFor = validFor(notification);
            final EmailMessage message = EmailMessage.of(null, to, composed.subject(), composed.body(),
                    composed.html(), composed.text()).withExpiresAt(validFor == null ? null : Instant.now().plus(validFor));
            final EmailSendOutcome outcome = outbox.send(RealmContextHolder.get(), message,
                    EmailOutbox.SendOptions.TRANSACTIONAL);
            final DeliveryResult result = outcome.result();
            if (result.reason() == DeliveryResult.Reason.NO_PROVIDER) {
                LOG.warn("No email provider configured (realm messaging provider or global "
                        + "helix.notification.email / smtp settings); dropping EMAIL notification (type={})",
                        notification.getType());
            } else if (result.isSuccess()) {
                LOG.info("Sent EMAIL notification (type={}): {}", notification.getType(), result.status());
            } else if (outcome.retryScheduled()) {
                LOG.warn("EMAIL notification (type={}) not delivered yet, a retry is queued: {} {}",
                        notification.getType(), result.status(), LogSafe.sanitize(result.diagnostic()));
            } else {
                LOG.warn("Failed to send EMAIL notification (type={}): {} {}", notification.getType(), result.status(),
                        LogSafe.sanitize(result.diagnostic()));
            }
        } catch (final RuntimeException e) {
            LOG.warn("Failed to send EMAIL notification (type={}): {}", notification.getType(),
                    LogSafe.sanitize(e.getClass().getSimpleName()));
        }
    }

    /**
     * How long the code or link in this notification works: its {@code ttlMinutes} / {@code ttlHours} data when the
     * sender gives one (the verification email), one hour for a password reset, else null (none).
     */
    static Duration validFor(final NotificationRequest notification) {
        final java.util.Map<String, String> data = notification.getAdditionalData();
        try {
            if (data != null && data.get("ttlMinutes") != null) {
                return Duration.ofMinutes(Long.parseLong(data.get("ttlMinutes").trim()));
            }
            if (data != null && data.get("ttlHours") != null) {
                return Duration.ofHours(Long.parseLong(data.get("ttlHours").trim()));
            }
        } catch (final NumberFormatException e) {
            // fall through to the type's default
        }
        return "USER_RESET_PASSWORD".equals(notification.getType()) ? RESET_EMAIL_VALID_FOR : null;
    }

    @Override
    public void sendSmsNotification(final NotificationRequest notification) {
        final String to = notification.getMobile();
        if (to == null || to.isBlank()) {
            LOG.warn("SMS notification (type={}) has no recipient mobile number; dropping", notification.getType());
            return;
        }

        final NotificationMessageComposer.ComposedMessage message = NotificationMessageComposer.compose(notification);
        try {
            final boolean sent = smsSender.send(to, message.body());
            if (!sent) {
                LOG.warn("No SMS provider configured for the current realm; dropping SMS notification (type={})",
                        notification.getType());
            } else {
                LOG.info("Sent SMS notification (type={})", notification.getType());
            }
        } catch (final RuntimeException e) {
            LOG.warn("Failed to send SMS notification (type={}): {}", notification.getType(), e.getMessage());
        }
    }

    @Override
    public void sendAppNotification(final NotificationRequest notification) {
        final NotificationMessageComposer.ComposedMessage message = NotificationMessageComposer.compose(notification);
        try {
            appSender.send(notification.getDeviceId(), message.subject(), message.body());
        } catch (final RuntimeException e) {
            LOG.warn("Failed to send APP notification (type={}): {}", notification.getType(), e.getMessage());
        }
    }

    /** The composer's email for this notification, else the plain-text fallback. */
    private EmailComposer.ComposedEmail composeEmail(final NotificationRequest notification) {
        if (emailComposer != null) {
            try {
                final java.util.Optional<EmailComposer.ComposedEmail> composed = emailComposer.compose(notification);
                if (composed.isPresent()) {
                    return composed.get();
                }
            } catch (final RuntimeException e) {
                LOG.warn("Email composer failed for type={}; sending the plain-text fallback: {}", notification.getType(),
                        LogSafe.sanitize(e.toString()));
            }
        }
        final NotificationMessageComposer.ComposedMessage plain = NotificationMessageComposer.compose(notification);
        return new EmailComposer.ComposedEmail(plain.subject(), plain.body(), false);
    }
}
