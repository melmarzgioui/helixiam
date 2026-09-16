package io.helixiam.authorization.domain.adminrbac.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM: one entry in the admin-permission catalogue (the console's matrix columns). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AdminPermissionDto(String key, String label) {
}
