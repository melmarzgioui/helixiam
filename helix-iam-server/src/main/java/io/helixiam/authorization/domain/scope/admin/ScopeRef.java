package io.helixiam.authorization.domain.scope.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5: identifies a scope (and optionally a claim) for detail / delete / map operations. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ScopeRef(String realmId, String scopeId, String claimId) {
}
