package group.mfnr.authorization.domain.user.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

/**
 * Helix IAM E8.5: create/update payload for a realm user (subscriber-side copy). {@code userId} is
 * null on create; {@code password} is only set when creating or explicitly changing the credential.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record UserWriteDto(String realmId, String userId, String username, String email, String password,
                           boolean enabled, boolean locked, Map<String, String> attributes) {
}
