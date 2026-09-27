/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import io.helixiam.authorization.amqp.messaging.MessagingAdminPublisher;
import io.helixiam.authorization.amqp.messaging.ResolveRequest;
import io.helixiam.authorization.observability.HelixMetrics;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.notification.delivery.SmtpProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Wires {@link EmailDelivery}: the realm's providers come from the messaging store at every send (no cache, so a
 * saved or rotated provider applies at once), the transports are every {@link EmailTransport} bean, and the global
 * default comes from {@code helix.notification.email.*}, {@code helix.notification.smtp.*} and
 * {@code helix.notification.cloudflare.*}.
 */
@Configuration
@EnableConfigurationProperties({EmailProperties.class, CloudflareProperties.class, SmtpProperties.class})
public class EmailDeliveryConfig {

    @Bean
    public GlobalEmailProvider globalEmailProvider(final EmailProperties email, final SmtpProperties smtp,
                                                   final CloudflareProperties cloudflare) {
        return new GlobalEmailProvider(email, smtp, cloudflare);
    }

    @Bean
    public EmailDelivery emailDelivery(final MessagingAdminPublisher publisher, final List<EmailTransport> transports,
                                       final GlobalEmailProvider global, final ObjectProvider<HelixMetrics> metrics,
                                       final ObjectProvider<AuditLog> audit) {
        return new EmailDelivery(realm -> publisher.enabledProviders(new ResolveRequest(realm, "EMAIL")), transports,
                global, metrics.getIfAvailable(), audit.getIfAvailable());
    }
}
