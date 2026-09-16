package io.helixiam.authorization.domain.scope.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Helix IAM E8.5: a client scope as the list/table shows it — name, description, claim count and a few
 * claim labels for preview. Mirrors the publisher copy.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientScopeDto(String realmId, String scopeId, String name, String description,
                             long claimCount, List<String> claimPreview) {
}
