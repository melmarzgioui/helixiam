package group.mfnr.authorization.domain.authz;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record AuthzPolicyDto(String id, String realmId, String clientId, String name, String type, String logic, List<String> roles) {
}
