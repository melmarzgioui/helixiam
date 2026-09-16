package io.helixiam.notification;

import io.helixiam.notification.domain.NotificationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * New (Task 1). Trivial fallback {@link Notifier}: logs instead of delivering, so the
 * application context can start and io.helixiam.notification.aop.NotificationAspect has
 * something to call even before a real delivery channel (SMTP/HTTP/push) is wired up in a later
 * task.
 *
 * <p>Task 5 (strip-RabbitMQ runtime reconciliation): this is no longer a {@code @Component} with
 * {@code @ConditionalOnMissingBean} — that combination is unreliable, because Spring only evaluates
 * {@code @ConditionalOnMissingBean} against beans processed so far and documents it as safe on
 * auto-configuration classes only. On a plain component-scanned bean it was skipped entirely, so no
 * {@link Notifier} was registered and the context failed to start. The fallback is now registered by
 * {@link NotificationFallbackConfig} via {@code @Bean @ConditionalOnMissingBean}, the reliable pattern;
 * a future concrete {@code Notifier} bean takes precedence with no change here.
 */
public class LoggingNotifier implements Notifier {

    private static final Logger LOG = LogManager.getLogger(NotificationConstant.MODULE_NAME);

    @Override
    public void sendEmailNotification(final NotificationRequest notification) {
        log("EMAIL", notification);
    }

    @Override
    public void sendSmsNotification(final NotificationRequest notification) {
        log("SMS", notification);
    }

    @Override
    public void sendAppNotification(final NotificationRequest notification) {
        log("APP", notification);
    }

    private void log(final String channel, final NotificationRequest notification) {
        LOG.warn("No Notifier implementation configured; dropping {} notification (type={}, code={})",
                channel, notification.getType(),
                notification.getNotificationCode() != null ? notification.getNotificationCode().getCode() : null);
    }
}
