package group.mfnr.authorization.domain.client.role;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM (Wave 4): create payload for a client role (subscriber copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientRoleWriteDto(String realmId, String clientId, String name, String description) {
}
