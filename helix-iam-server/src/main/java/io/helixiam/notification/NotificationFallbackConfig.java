package io.helixiam.notification;

import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Task 5 (strip-RabbitMQ runtime reconciliation) / Task 4 (real delivery). Registers the
 * {@link LoggingNotifier} fallback.
 *
 * <p>{@code @Bean @ConditionalOnMissingBean} alone is NOT reliable here, even inside a
 * {@code @Configuration} class: that guarantee only holds for beans declared later in the SAME
 * configuration class (or true auto-configuration, ordered via {@code AutoConfiguration.imports}).
 * Across two independently component-scanned {@code @Configuration} classes — this one and
 * {@code io.helixiam.notification.delivery.NotificationDeliveryConfig}, which registers the real
 * {@link io.helixiam.notification.delivery.SmtpNotifier} — Spring does not guarantee which is parsed
 * first, so {@code @ConditionalOnMissingBean(Notifier.class)} alone intermittently saw NO other
 * {@link Notifier} bean yet and registered {@code loggingNotifier} alongside {@code smtpNotifier},
 * which then failed context startup with {@code NoUniqueBeanDefinitionException}. The
 * {@code @ConditionalOnExpression} below makes the two conditions structurally mutually exclusive
 * (mirrors the negation of {@code NotificationDeliveryConfig}'s
 * {@code @ConditionalOnProperty(havingValue = "smtp", matchIfMissing = true)}), so exactly one
 * {@link Notifier} bean exists regardless of class-processing order.
 * {@code @ConditionalOnMissingBean} is kept too, as a defense-in-depth guard for any future
 * {@link Notifier} implementation that doesn't use {@code helix.notification.provider} at all.
 */
@Configuration
public class NotificationFallbackConfig {

    @Bean
    @ConditionalOnMissingBean(Notifier.class)
    @ConditionalOnExpression("!'smtp'.equalsIgnoreCase('${helix.notification.provider:smtp}')")
    public Notifier loggingNotifier() {
        return new LoggingNotifier();
    }
}
