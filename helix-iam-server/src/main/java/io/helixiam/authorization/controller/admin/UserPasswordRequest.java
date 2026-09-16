package io.helixiam.authorization.controller.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Helix IAM E8.5: admin password-reset request body. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record UserPasswordRequest(@NotBlank(message = "New password is required.") @Size(min = 1, message = "New password is required.") String newPassword) {
}
