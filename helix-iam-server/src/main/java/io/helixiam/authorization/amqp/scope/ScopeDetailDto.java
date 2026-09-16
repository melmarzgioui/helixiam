package io.helixiam.authorization.amqp.scope;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/** Helix IAM E8.5: a client scope with its full claim list (mirrors the subscriber copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ScopeDetailDto(String realmId, String scopeId, String name, String description, List<ClaimDto> claims) {
}
