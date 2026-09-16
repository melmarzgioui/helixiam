package group.mfnr.authorization.domain.user.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5: identifies one factor to revoke for a realm user (subscriber-side copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CredentialRevokeRef(String realmId, String userId, String type, String id) {
}
