package group.mfnr.authorization.domain.client.role;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM (Wave 4): a role granted to a client's service account (subscriber copy). Doubles as the
 * assign/unassign payload ({@code id} is null on assign). {@code roleType} is {@code REALM} or {@code CLIENT};
 * {@code roleClientId} names the owning client for {@code CLIENT} roles.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ServiceAccountRoleDto(String id, String realmId, String clientId, String roleName,
                                    String roleType, String roleClientId) {
}
