/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.notification.delivery.spi;

/**
 * Task 4 (strip-RabbitMQ notification delivery). Extension point for SMS dispatch used by
 * {@link io.helixiam.notification.delivery.SmtpNotifier}. The default implementation
 * ({@code io.helixiam.notification.delivery.RealmSmsSender}) reuses the realm's already-configured
 * {@code io.helixiam.authorization.messaging.driver.SmsDriver} (Twilio/HTTP) when one is enabled for
 * the in-flight realm; it returns {@code false} when nothing is configured so the caller can log and
 * move on instead of failing the underlying request.
 *
 * <p>To add a different default SMS gateway (independent of the per-realm messaging providers),
 * register another {@code @Component}/{@code @Bean} implementing this interface — it wins over the
 * default automatically via {@code @ConditionalOnMissingBean} in
 * {@code io.helixiam.notification.delivery.NotificationDeliveryConfig}.
 */
public interface SmsSender {

    /**
     * Attempt to deliver {@code message} to {@code to}.
     *
     * @return {@code true} if a provider actually dispatched the message; {@code false} if nothing is
     *         configured (not an error — the caller logs and continues).
     */
    boolean send(String to, String message);
}
