package io.helixiam.authorization.domain.provisioning.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM E11: save payload for the realm provisioning config (subscriber copy). A {@code null}
 * {@code dcrOpen} leaves the policy unchanged; {@code rotateScimToken=true} requests a new SCIM token.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ProvisioningConfigWriteDto(String realmId, Boolean dcrOpen, boolean rotateScimToken,
                                         boolean clearScimToken) {
}
