package group.mfnr.authorization.amqp.authz;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record AuthzServerDto(String realmId, String clientId, Boolean enabled, String decisionStrategy) {
}
