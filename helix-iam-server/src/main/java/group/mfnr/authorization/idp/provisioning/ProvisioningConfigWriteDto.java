package group.mfnr.authorization.idp.provisioning;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E11: save payload for the realm provisioning config (publisher copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ProvisioningConfigWriteDto(String realmId, Boolean dcrOpen, boolean rotateScimToken,
                                         boolean clearScimToken) {
}
