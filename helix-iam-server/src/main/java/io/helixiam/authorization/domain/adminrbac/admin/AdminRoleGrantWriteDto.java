package io.helixiam.authorization.domain.adminrbac.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/** Helix IAM: set the complete set of admin-permission {@code key}s granted to one realm admin role. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AdminRoleGrantWriteDto(String realmId, String roleId, List<String> permissions) {
}
