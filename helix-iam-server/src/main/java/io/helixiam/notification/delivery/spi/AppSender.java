/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.notification.delivery.spi;

/**
 * Task 4 (strip-RabbitMQ notification delivery). Extension point for in-app/push dispatch used by
 * {@link io.helixiam.notification.delivery.SmtpNotifier}. Not wired to a real push gateway yet — see
 * {@code io.helixiam.notification.delivery.LoggingAppSender} for why (HelixIAM's existing push
 * pipeline, {@code io.helixiam.authorization.messaging.MessagingService#sendPush}, keys off a user's
 * registered device tokens, not the single {@code deviceId} string carried on the legacy
 * {@code NotificationRequest} this SPI dispatches).
 *
 * <p>To wire real push (FCM/APNS/webhook), register a {@code @Component}/{@code @Bean} implementing
 * this interface — it wins over {@code LoggingAppSender} automatically via
 * {@code @ConditionalOnMissingBean} in {@code io.helixiam.notification.delivery.NotificationDeliveryConfig}.
 */
public interface AppSender {

    /** Deliver a push/in-app notification to {@code deviceId}. */
    void send(String deviceId, String title, String body);
}
