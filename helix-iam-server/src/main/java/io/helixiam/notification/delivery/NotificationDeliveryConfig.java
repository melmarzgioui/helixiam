/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.notification.delivery;

import io.helixiam.authorization.messaging.driver.EmailDriver;
import io.helixiam.authorization.messaging.driver.SmsDriver;
import io.helixiam.authorization.repository.messaging.MessagingProviderRepository;
import io.helixiam.notification.Notifier;
import io.helixiam.notification.delivery.spi.AppSender;
import io.helixiam.notification.delivery.spi.SmsSender;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Task 4 (strip-RabbitMQ notification delivery). Registers the real {@link Notifier} —
 * {@link SmtpNotifier} — and its {@link SmsSender}/{@link AppSender} collaborators, all
 * property-selectable and each independently overridable:
 *
 * <ul>
 *   <li>{@code helix.notification.provider=smtp} (default) registers {@link SmtpNotifier} as the
 *       {@link Notifier}. Set it to anything else (e.g. {@code log}) to skip it and fall back to
 *       {@code io.helixiam.notification.LoggingNotifier} via
 *       {@code io.helixiam.notification.NotificationFallbackConfig}'s
 *       {@code @ConditionalOnMissingBean(Notifier.class)} — the same reliable default-backs-off
 *       pattern used there, kept intact here.</li>
 *   <li>{@link SmsSender} defaults to {@link RealmSmsSender} (reuses the realm's configured SMS
 *       driver); {@link AppSender} defaults to {@link LoggingAppSender} (push not wired yet — see its
 *       javadoc). Either backs off automatically when a more specific bean is registered elsewhere.</li>
 * </ul>
 */
@Configuration
@EnableConfigurationProperties(SmtpProperties.class)
public class NotificationDeliveryConfig {

    @Bean
    @ConditionalOnMissingBean(SmsSender.class)
    public SmsSender realmSmsSender(final List<SmsDriver> smsDrivers, final MessagingProviderRepository providerRepository) {
        return new RealmSmsSender(smsDrivers, providerRepository);
    }

    @Bean
    @ConditionalOnMissingBean(AppSender.class)
    public AppSender loggingAppSender() {
        return new LoggingAppSender();
    }

    @Bean
    @ConditionalOnProperty(name = "helix.notification.provider", havingValue = "smtp", matchIfMissing = true)
    public Notifier smtpNotifier(final List<EmailDriver> emailDrivers, final MessagingProviderRepository providerRepository,
            final SmsSender smsSender, final AppSender appSender, final SmtpProperties smtpProperties) {
        return new SmtpNotifier(emailDrivers, providerRepository, smsSender, appSender, smtpProperties);
    }
}
