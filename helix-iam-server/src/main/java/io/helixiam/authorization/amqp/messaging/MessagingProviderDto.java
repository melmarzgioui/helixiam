package io.helixiam.authorization.amqp.messaging;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

/** Helix IAM notifications (N2): publisher-side view of a messaging provider (secret masked → secretSet). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record MessagingProviderDto(String id, String realmId, String channel, String driver, boolean enabled,
                                   String fromAddress, String fromName, Map<String, String> config, boolean secretSet) {
}
