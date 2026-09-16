package io.helixiam.authorization.amqp.authz;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record AuthzPermissionDto(String id, String realmId, String clientId, String name, String type, String resourceName, String scopeName, List<String> policies, String decisionStrategy) {
}
