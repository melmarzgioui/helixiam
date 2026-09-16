package group.mfnr.authorization.amqp.group;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/** Helix IAM E8.5-S4: publisher-side view of a group (mirrors the subscriber's domain copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GroupDto(String realmId, String groupId, String name, String parentId, long memberCount,
                       List<String> roleNames) {
}
