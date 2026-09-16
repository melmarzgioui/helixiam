package io.helixiam.authorization.controller.account;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;

/**
 * Helix IAM (6) Self-service Account: change-own-password body — both the current password (verified before
 * the change) and the new password are required. Validated with Bean Validation so a missing field is a clean
 * 400 rather than a thrown exception (which the security chain would turn into a 302 to /login).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AccountPasswordRequest(@NotBlank(message = "Current password is required.") String currentPassword,
                                     @NotBlank(message = "New password is required.") String newPassword) {
}
