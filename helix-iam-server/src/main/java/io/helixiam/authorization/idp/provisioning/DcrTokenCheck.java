/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.provisioning;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E11: verify a registration_access_token against a client's binding (publisher copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record DcrTokenCheck(String realmId, String clientInternalId, String token) {
}
