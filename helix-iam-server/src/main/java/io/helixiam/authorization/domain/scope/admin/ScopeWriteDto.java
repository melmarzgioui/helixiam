package io.helixiam.authorization.domain.scope.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5: create payload for a client scope. Mirrors the publisher copy. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ScopeWriteDto(String realmId, String name, String description) {
}
