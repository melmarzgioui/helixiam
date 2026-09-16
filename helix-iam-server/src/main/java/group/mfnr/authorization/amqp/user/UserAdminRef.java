package group.mfnr.authorization.amqp.user;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5: identifies a single realm user (publisher-side copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record UserAdminRef(String realmId, String userId) {
}
