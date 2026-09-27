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
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import io.helixiam.persistence.security.AttributeEncryption;

import java.time.Clock;
import java.util.List;

/**
 * Wires {@link EmailDelivery}: the realm's providers come from the messaging store at every send (no cache, so a
 * saved or rotated provider applies at once), the transports are every {@link EmailTransport} bean, and the global
 * default comes from {@code helix.notification.email.*}, {@code helix.notification.smtp.*} and
 * {@code helix.notification.cloudflare.*}. Around it, {@link EmailOutbox}: the send rate caps, the persisted retry
 * queue ({@link JdbcEmailRetryStore}, worked off by {@link EmailRetryWorker}) and bounce marking
 * ({@link JdbcBounceRecorder}). Without a database (slice tests), the outbox only makes the synchronous attempt.
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

    @Bean
    public EmailSendRateCap emailSendRateCap(final EmailProperties email) {
        return new EmailSendRateCap(email.getRateLimit(), Clock.systemUTC());
    }

    /** Bounced addresses on the user; absent without a database. */
    @Bean
    public JdbcBounceRecorder emailBounces(final ObjectProvider<JdbcTemplate> jdbc,
                                           final ObjectProvider<PlatformTransactionManager> transactions) {
        final JdbcTemplate template = jdbc.getIfAvailable();
        final PlatformTransactionManager tm = transactions.getIfAvailable();
        return template == null || tm == null ? null : new JdbcBounceRecorder(template, tm);
    }

    @Bean
    public EmailOutbox emailOutbox(final EmailDelivery delivery, final EmailProperties email,
                                   final EmailSendRateCap rateCap, final ObjectProvider<JdbcTemplate> jdbc,
                                   final ObjectProvider<PlatformTransactionManager> transactions,
                                   final ObjectProvider<JdbcBounceRecorder> bounces, final Environment environment,
                                   final ObjectProvider<HelixMetrics> metrics, final ObjectProvider<AuditLog> audit) {
        final JdbcTemplate template = jdbc.getIfAvailable();
        final PlatformTransactionManager tm = transactions.getIfAvailable();
        EmailRetryStore store = null;
        if (template != null && tm != null) {
            // The same key as every other encrypted column (database.encryption / DB_ENCRYPTION).
            final String key = environment.getProperty("database.encryption");
            store = new JdbcEmailRetryStore(template, tm, key == null || key.isBlank() ? null
                    : new AttributeEncryption(key));
        }
        return new EmailOutbox(delivery, store, rateCap, bounces.getIfAvailable(), email, metrics.getIfAvailable(),
                audit.getIfAvailable(), Clock.systemUTC());
    }

    @Bean
    public EmailRetryWorker emailRetryWorker(final EmailOutbox outbox, final EmailProperties email) {
        return new EmailRetryWorker(outbox, email.getRetry().getPollInterval(), email.getRetry().isEnabled());
    }
}
