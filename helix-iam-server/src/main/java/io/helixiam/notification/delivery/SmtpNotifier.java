package io.helixiam.notification.delivery;

import group.mfnr.authorization.amqp.messaging.ResolvedProviderDto;
import group.mfnr.authorization.domain.messaging.MessagingProvider;
import group.mfnr.authorization.messaging.driver.EmailDriver;
import group.mfnr.authorization.repository.messaging.MessagingProviderRepository;
import group.mfnr.authorization.security.realm.RealmContextHolder;
import io.helixiam.notification.NotificationConstant;
import io.helixiam.notification.Notifier;
import io.helixiam.notification.delivery.spi.AppSender;
import io.helixiam.notification.delivery.spi.SmsSender;
import io.helixiam.notification.domain.NotificationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;
import java.util.Map;
import java.util.Optional;

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
 * {@code group.mfnr.authorization.messaging.MessagingService} reads for the OTP/magic-link email
 * senders — dispatched through whichever {@link EmailDriver} (SMTP or HTTP) matches that provider's
 * {@code driver} id. Falls back to the {@link SmtpProperties} global SMTP config
 * ({@code helix.notification.smtp.*}) only when the realm has none enabled (or there is no realm in
 * context, e.g. for the platform-level {@code USER_SIGNUP}/{@code USER_RESET_PASSWORD} notifications
 * fired from the default/master realm's public signup and reset-password endpoints). When neither is
 * configured, the notification is logged and dropped — never an exception, never a hang.
 */
public class SmtpNotifier implements Notifier {

    private static final Logger LOG = LogManager.getLogger(NotificationConstant.MODULE_NAME);
    private static final String EMAIL_CHANNEL = "EMAIL";
    private static final String SMTP_DRIVER = "SMTP";

    private final List<EmailDriver> emailDrivers;
    private final MessagingProviderRepository providerRepository;
    private final SmsSender smsSender;
    private final AppSender appSender;
    private final SmtpProperties smtpProperties;

    public SmtpNotifier(final List<EmailDriver> emailDrivers, final MessagingProviderRepository providerRepository,
                        final SmsSender smsSender, final AppSender appSender, final SmtpProperties smtpProperties) {
        this.emailDrivers = emailDrivers;
        this.providerRepository = providerRepository;
        this.smsSender = smsSender;
        this.appSender = appSender;
        this.smtpProperties = smtpProperties;
    }

    @Override
    public void sendEmailNotification(final NotificationRequest notification) {
        final String to = notification.getEmailAddress();
        if (to == null || to.isBlank()) {
            LOG.warn("EMAIL notification (type={}) has no recipient address; dropping", notification.getType());
            return;
        }

        final NotificationMessageComposer.ComposedMessage message = NotificationMessageComposer.compose(notification);
        try {
            final ResolvedEmail resolved = resolveEmailDriver();
            if (resolved == null) {
                LOG.warn("No email provider configured (realm messaging provider or global "
                        + "helix.notification.smtp.host); dropping EMAIL notification (type={})", notification.getType());
                return;
            }
            resolved.driver().send(resolved.provider(), to, message.subject(), message.body(), false);
            LOG.info("Sent EMAIL notification (type={}) via {}", notification.getType(), resolved.provider().driver());
        } catch (final RuntimeException e) {
            LOG.warn("Failed to send EMAIL notification (type={}): {}", notification.getType(), e.getMessage());
        }
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

    private record ResolvedEmail(EmailDriver driver, ResolvedProviderDto provider) {
    }

    private ResolvedEmail resolveEmailDriver() {
        final String realm = RealmContextHolder.get();
        if (realm != null) {
            final Optional<MessagingProvider> enabled = providerRepository.findByRealmIdAndChannel(realm, EMAIL_CHANNEL)
                    .stream().filter(p -> Boolean.TRUE.equals(p.getEnabled())).findFirst();
            if (enabled.isPresent()) {
                final MessagingProvider provider = enabled.get();
                final EmailDriver driver = findDriver(provider.getDriver());
                if (driver != null) {
                    return new ResolvedEmail(driver, MessagingProviderMapper.toResolvedProviderDto(provider));
                }
                LOG.warn("Realm {} has an EMAIL provider configured with unknown driver '{}'; falling back to global SMTP",
                        realm, provider.getDriver());
            }
        }

        if (smtpProperties.getHost() == null || smtpProperties.getHost().isBlank()) {
            return null;
        }
        final EmailDriver smtpDriver = findDriver(SMTP_DRIVER);
        if (smtpDriver == null) {
            return null;
        }
        return new ResolvedEmail(smtpDriver, globalProvider());
    }

    private EmailDriver findDriver(final String driverId) {
        return emailDrivers.stream().filter(d -> d.driver().equalsIgnoreCase(driverId)).findFirst().orElse(null);
    }

    private ResolvedProviderDto globalProvider() {
        return new ResolvedProviderDto(EMAIL_CHANNEL, SMTP_DRIVER, smtpProperties.getFromAddress(), smtpProperties.getFromName(),
                Map.of(
                        "host", smtpProperties.getHost(),
                        "port", String.valueOf(smtpProperties.getPort()),
                        "username", smtpProperties.getUsername() == null ? "" : smtpProperties.getUsername(),
                        "starttls", String.valueOf(smtpProperties.isStarttls())),
                smtpProperties.getPassword());
    }
}
