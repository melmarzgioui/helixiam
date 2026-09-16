package io.helixiam.authorization.domain.provisioning.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM E11: subscriber-side view of a realm's provisioning configuration (two-copy DTO; mirrors the
 * publisher copy). {@code scimTokenSet} reports whether a SCIM token exists without exposing it.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ProvisioningConfigDto(String realmId, boolean scimTokenSet, boolean dcrOpen) {
}
