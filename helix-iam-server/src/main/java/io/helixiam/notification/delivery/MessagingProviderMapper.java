package io.helixiam.notification.delivery;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.authorization.domain.messaging.MessagingProvider;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Task 4 (strip-RabbitMQ notification delivery). Maps a persisted {@link MessagingProvider} row (the
 * realm's own SMTP/HTTP/Twilio/... config, entered via the "Messaging" realm-settings screen) to the
 * {@link ResolvedProviderDto} the existing {@code EmailDriver}/{@code SmsDriver} beans expect —
 * mirrors {@code io.helixiam.authorization.service.messaging.MessagingAdminService#readJson}, kept
 * private to that service, so this is a small local copy rather than a new cross-package dependency.
 */
final class MessagingProviderMapper {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private MessagingProviderMapper() {
    }

    static ResolvedProviderDto toResolvedProviderDto(final MessagingProvider provider) {
        return new ResolvedProviderDto(provider.getChannel(), provider.getDriver(), provider.getFromAddress(),
                provider.getFromName(), readConfig(provider.getConfig()), provider.getSecret());
    }

    private static Map<String, String> readConfig(final String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return OBJECT_MAPPER.readValue(json, new TypeReference<LinkedHashMap<String, String>>() { });
        } catch (final Exception e) {
            return Map.of();
        }
    }
}
