package io.helixiam.authorization.amqp.user;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

/** Helix IAM E8.5: create/update payload for a realm user (publisher-side copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record UserWriteDto(String realmId, String userId, String username, String email, String password,
                           boolean enabled, boolean locked, Map<String, String> attributes) {
}
