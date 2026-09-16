package group.mfnr.authorization.controller.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;

/** Helix IAM E8.5-S2: create-realm-role request body. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RoleNameRequest(@NotBlank(message = "Role name is required.") String name) {
}
