package io.helixiam.authorization.domain.messaging.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

/**
 * Helix IAM notifications (N1): create/update payload for a messaging provider. {@code secret} is
 * write-only — {@code null}/blank keeps the stored secret, a value replaces it.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record MessagingProviderWriteDto(String realmId, String channel, String driver, boolean enabled,
                                        String fromAddress, String fromName, Map<String, String> config,
                                        String secret) {
}
