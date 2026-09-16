/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.notification;

import io.helixiam.notification.domain.NotificationRequest;

/**
 * New interface (Task 1) replacing io.helixiam.subscriber.starter.notification.amqp.NotificationPublisher.
 *
 * The original NotificationPublisher was a @FederatedPublisher AMQP interface: each method fired
 * an @AnonymousSender message onto a RabbitMQ exchange/routing-key (email/sms/app), and a separate
 * subscriber elsewhere in the mfnr platform did the actual delivery. HelixIAM has no broker, so
 * this interface captures the exact same three call sites (used by
 * io.helixiam.notification.aop.NotificationAspect) but as a plain synchronous, in-process Java
 * contract. Delivery implementations (SMTP, HTTP webhook, push, etc.) are a later task; see
 * {@link LoggingNotifier} for the no-op/log fallback that lets the context start meanwhile.
 */
public interface Notifier {

    void sendEmailNotification(final NotificationRequest notification);

    void sendSmsNotification(final NotificationRequest notification);

    void sendAppNotification(final NotificationRequest notification);
}
