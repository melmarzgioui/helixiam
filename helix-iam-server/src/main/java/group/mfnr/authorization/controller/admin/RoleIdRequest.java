package group.mfnr.authorization.controller.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;

/** Helix IAM E8.5-S2: assign-role request body (the role to grant). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RoleIdRequest(@NotBlank(message = "Role id is required.") String roleId) {
}
