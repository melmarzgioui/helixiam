package group.mfnr.authorization.domain.org.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM Organizations: a member of an organization — user id, username, and role within the org. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OrgMemberDto(String userId, String username, String role) {
}
