package group.mfnr.authorization.domain.adminrbac.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Helix IAM: a realm (admin) role together with the admin-permission {@code key}s it currently grants —
 * one row of the console's role × permission matrix.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AdminRoleGrantsDto(String realmId, String roleId, String roleName, List<String> permissions) {
}
