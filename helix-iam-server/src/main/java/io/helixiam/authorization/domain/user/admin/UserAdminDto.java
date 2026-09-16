package io.helixiam.authorization.domain.user.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;
import java.util.Map;

/**
 * Helix IAM E8.5: subscriber-side view of a realm user for the admin console (two-copy DTO; mirrors
 * the publisher's {@code amqp.user.UserAdminDto}). Read-only projection assembled from the global
 * {@code user_credentials} row plus the realm's {@code tenant_user} link and its role assignments.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record UserAdminDto(String realmId, String userId, String username, String email, boolean enabled,
                           boolean locked, boolean mfaEnabled, List<String> roles, Map<String, String> attributes,
                           Long createdAt) {
}
