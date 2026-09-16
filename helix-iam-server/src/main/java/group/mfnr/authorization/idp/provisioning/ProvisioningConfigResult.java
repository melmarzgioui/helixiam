package group.mfnr.authorization.idp.provisioning;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E11: result of a provisioning-config save (publisher copy); {@code newScimToken} returned once. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ProvisioningConfigResult(ProvisioningConfigDto config, String newScimToken) {
}
