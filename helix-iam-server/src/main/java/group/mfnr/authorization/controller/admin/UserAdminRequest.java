package group.mfnr.authorization.controller.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.Map;

/**
 * Helix IAM E8.5: create/update request body for a realm user. {@code password} is only honoured on
 * create; {@code enabled} defaults to true when omitted so a new user is active unless disabled.
 * Password is intentionally unconstrained here (the same record is reused for update where it is optional);
 * "password required on create" is guarded in the subscriber's {@code UserAdminService.create}.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record UserAdminRequest(@NotBlank(message = "Username is required.") @Size(max = 255, message = "Username must be at most 255 characters.") String username,
                               @Email(message = "Email must be a valid address.") String email,
                               String password, Boolean enabled, boolean locked,
                               Map<String, String> attributes) {

    public boolean enabledOrDefault() {
        return enabled == null || enabled;
    }
}
