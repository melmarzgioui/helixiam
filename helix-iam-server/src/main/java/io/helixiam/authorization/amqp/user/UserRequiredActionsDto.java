package io.helixiam.authorization.amqp.user;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM B1: publisher-side copy of the user required-actions DTO (two-copy; same field order for
 * Jackson-over-AMQP). For {@code set} it's the full CSV; for {@code clear} the {@code requiredActions}
 * field carries the single action to remove.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record UserRequiredActionsDto(String realmId, String userId, String requiredActions) {
}
