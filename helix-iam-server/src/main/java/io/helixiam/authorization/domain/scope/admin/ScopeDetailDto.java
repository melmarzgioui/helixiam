package io.helixiam.authorization.domain.scope.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/** Helix IAM E8.5: a client scope with its full claim list — backs the scope detail page. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ScopeDetailDto(String realmId, String scopeId, String name, String description,
                             List<ClaimDto> claims) {
}
