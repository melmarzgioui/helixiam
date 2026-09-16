package group.mfnr.authorization.amqp.user;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;
import java.util.Map;

/**
 * Helix IAM E8.5: publisher-side view of a realm user (two-copy DTO; mirrors the subscriber's
 * {@code domain.user.admin.UserAdminDto}). Returned by the Users admin API.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record UserAdminDto(String realmId, String userId, String username, String email, boolean enabled,
                           boolean locked, boolean mfaEnabled, List<String> roles, Map<String, String> attributes,
                           Long createdAt) {
}
