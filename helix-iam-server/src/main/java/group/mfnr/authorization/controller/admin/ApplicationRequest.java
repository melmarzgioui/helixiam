package group.mfnr.authorization.controller.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Helix IAM: create/update request body for an Application — the protocol-agnostic parent that owns the
 * shared subject claim + login flow.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ApplicationRequest(@NotBlank(message = "Application name is required.") @Size(max = 255, message = "Application name must be at most 255 characters.") String name,
                                 String description, String subjectClaim, String authFlowAlias,
                                 Boolean enabled, String displayName) {
}
