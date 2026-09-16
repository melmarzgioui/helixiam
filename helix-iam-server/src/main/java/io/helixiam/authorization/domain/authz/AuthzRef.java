package io.helixiam.authorization.domain.authz;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record AuthzRef(String realmId, String clientId, String name) {
}
