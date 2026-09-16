package io.helixiam.authorization.domain.authz;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record AuthzEvalRequest(String realmId, String clientId, String username, List<String> roles, String resourceName, String scopeName) {
}
