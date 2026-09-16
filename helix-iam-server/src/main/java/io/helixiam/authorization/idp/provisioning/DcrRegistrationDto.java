/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.provisioning;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E11: a DCR registration binding (publisher copy); {@code registrationToken} returned once. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record DcrRegistrationDto(String registrationId, String realmId, String clientInternalId,
                                 String clientId, String registrationToken) {
}
