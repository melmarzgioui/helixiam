package io.helixiam.authorization.domain.user.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM B1: carries a user's required-actions CSV across the AMQP seam (subscriber copy). For
 * {@code set} it is the full replacement list; for {@code clear} the {@code requiredActions} field holds
 * the single action to remove.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record UserRequiredActionsDto(String realmId, String userId, String requiredActions) {
}
