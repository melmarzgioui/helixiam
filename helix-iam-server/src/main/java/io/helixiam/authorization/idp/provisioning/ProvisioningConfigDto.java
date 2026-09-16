/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.provisioning;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E11: publisher-side view of a realm's provisioning config (mirrors the subscriber copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ProvisioningConfigDto(String realmId, boolean scimTokenSet, boolean dcrOpen) {
}
