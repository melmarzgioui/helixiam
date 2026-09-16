package group.mfnr.authorization.amqp.clientrole;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM (Wave 4): a client role (publisher copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientRoleDto(String roleId, String realmId, String clientId, String name, String description) {
}
