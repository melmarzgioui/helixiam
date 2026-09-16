package io.helixiam.authorization.amqp.group;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5-S4: create/rename payload for a group (mirrors the subscriber copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GroupWriteDto(String realmId, String groupId, String name, String parentId) {
}
