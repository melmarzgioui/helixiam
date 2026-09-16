package io.helixiam.authorization.domain.role.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5-S2: assign/unassign a role to a user within a realm (subscriber-side copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RoleAssignment(String realmId, String userId, String roleId) {
}
