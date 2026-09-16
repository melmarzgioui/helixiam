package io.helixiam.authorization.domain.user.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM (6) Self-service Account: a user changing <em>their own</em> password — unlike the admin
 * reset, the current password must be supplied and verified before the new one is set (subscriber copy).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record UserChangePasswordDto(String realmId, String userId, String currentPassword, String newPassword) {
}
