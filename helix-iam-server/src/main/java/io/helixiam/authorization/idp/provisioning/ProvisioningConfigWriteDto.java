/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.provisioning;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E11: save payload for the realm provisioning config (publisher copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ProvisioningConfigWriteDto(String realmId, Boolean dcrOpen, boolean rotateScimToken,
                                         boolean clearScimToken) {
}
