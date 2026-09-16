package io.helixiam.notification.delivery;

import group.mfnr.authorization.amqp.messaging.ResolvedProviderDto;
import group.mfnr.authorization.domain.messaging.MessagingProvider;
import group.mfnr.authorization.messaging.driver.SmsDriver;
import group.mfnr.authorization.repository.messaging.MessagingProviderRepository;
import group.mfnr.authorization.security.realm.RealmContextHolder;
import io.helixiam.notification.delivery.spi.SmsSender;

import java.util.List;
import java.util.Optional;

/**
 * Task 4 (strip-RabbitMQ notification delivery). Default {@link SmsSender}: reuses whichever
 * {@code SmsDriver} (Twilio/HTTP — already real, see {@code group.mfnr.authorization.messaging.driver})
 * the in-flight realm has enabled under its {@code SMS} messaging provider, exactly like the realm
 * OTP/magic-link senders do. Returns {@code false} (never throws) when there is no realm in context or
 * no enabled SMS provider, so {@link SmtpNotifier} can log and continue instead of failing the caller.
 */
public class RealmSmsSender implements SmsSender {

    private final List<SmsDriver> smsDrivers;
    private final MessagingProviderRepository providerRepository;

    public RealmSmsSender(final List<SmsDriver> smsDrivers, final MessagingProviderRepository providerRepository) {
        this.smsDrivers = smsDrivers;
        this.providerRepository = providerRepository;
    }

    @Override
    public boolean send(final String to, final String message) {
        final String realm = RealmContextHolder.get();
        if (realm == null) {
            return false;
        }

        final Optional<MessagingProvider> enabled = providerRepository.findByRealmIdAndChannel(realm, "SMS").stream()
                .filter(p -> Boolean.TRUE.equals(p.getEnabled())).findFirst();
        if (enabled.isEmpty()) {
            return false;
        }

        final MessagingProvider provider = enabled.get();
        final SmsDriver driver = smsDrivers.stream().filter(d -> d.driver().equalsIgnoreCase(provider.getDriver()))
                .findFirst().orElse(null);
        if (driver == null) {
            return false;
        }

        final ResolvedProviderDto resolved = MessagingProviderMapper.toResolvedProviderDto(provider);
        driver.send(resolved, to, message);
        return true;
    }
}
