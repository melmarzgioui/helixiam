package group.mfnr.authorization.domain.provisioning.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM E11: result of a provisioning-config save (subscriber copy). {@code newScimToken} is the
 * freshly-generated SCIM token, returned exactly once when {@code rotateScimToken} was requested.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ProvisioningConfigResult(ProvisioningConfigDto config, String newScimToken) {
}
