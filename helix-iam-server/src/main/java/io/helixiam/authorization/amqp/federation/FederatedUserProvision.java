package io.helixiam.authorization.amqp.federation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

/**
 * Helix IAM E5.3: AMQP request DTO — just-in-time provision a conservative federated user from a
 * brokered identity's email + mapped attributes. JSON-marshalled, two-copy on each side.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FederatedUserProvision(String email, Map<String, String> attributes) {
}
