package io.helixiam.authorization.domain.group.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5-S4: identifies a group, optionally with a target user or role for membership/role ops. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GroupRef(String realmId, String groupId, String userId, String roleId) {
}
