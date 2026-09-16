package io.helixiam.authorization.amqp.group;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5-S4: identifies a group, optionally with a target user or role (mirrors subscriber copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GroupRef(String realmId, String groupId, String userId, String roleId) {
}
