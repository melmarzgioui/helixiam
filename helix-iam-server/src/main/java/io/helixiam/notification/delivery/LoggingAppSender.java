package io.helixiam.notification.delivery;

import io.helixiam.notification.NotificationConstant;
import io.helixiam.notification.delivery.spi.AppSender;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Task 4 (strip-RabbitMQ notification delivery). Default {@link AppSender}: logs instead of delivering
 * — see the {@link AppSender} javadoc for why push isn't wired to a real gateway here yet, and how to
 * add one.
 */
public class LoggingAppSender implements AppSender {

    private static final Logger LOG = LogManager.getLogger(NotificationConstant.MODULE_NAME);

    @Override
    public void send(final String deviceId, final String title, final String body) {
        LOG.warn("No AppSender implementation configured; dropping APP/push notification (deviceId={})", deviceId);
    }
}
