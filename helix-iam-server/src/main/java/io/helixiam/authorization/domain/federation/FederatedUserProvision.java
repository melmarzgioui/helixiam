package io.helixiam.authorization.domain.federation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

/**
 * Helix IAM E5.3: AMQP request DTO — just-in-time provision a conservative federated user from a
 * brokered identity's email + mapped attributes. Two-copy mirror of the publisher's DTO.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FederatedUserProvision(String email, Map<String, String> attributes) {
}
