package group.mfnr.authorization.amqp.group;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5-S4: a member of a group — user id and username (mirrors the subscriber copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GroupMemberDto(String userId, String username) {
}
