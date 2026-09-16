package io.helixiam.authorization.domain.group.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Helix IAM E8.5-S4: a group as the console shows it — realm, id, name, parent (null at top level),
 * member count and the names of the realm roles mapped onto it. Mirrors the publisher copy.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GroupDto(String realmId, String groupId, String name, String parentId, long memberCount,
                       List<String> roleNames) {
}
