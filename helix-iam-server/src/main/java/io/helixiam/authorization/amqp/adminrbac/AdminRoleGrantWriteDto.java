package io.helixiam.authorization.amqp.adminrbac;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/** Helix IAM: set the complete set of admin-permission keys for one realm admin role (publisher copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AdminRoleGrantWriteDto(String realmId, String roleId, List<String> permissions) {
}
