package group.mfnr.authorization.domain.role.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5-S2: a realm role create request / reference (subscriber-side copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RoleRef(String realmId, String roleId, String name) {
}
