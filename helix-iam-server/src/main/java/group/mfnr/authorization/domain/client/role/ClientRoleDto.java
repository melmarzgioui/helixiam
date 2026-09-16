package group.mfnr.authorization.domain.client.role;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM (Wave 4): a client role (subscriber copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientRoleDto(String roleId, String realmId, String clientId, String name, String description) {
}
