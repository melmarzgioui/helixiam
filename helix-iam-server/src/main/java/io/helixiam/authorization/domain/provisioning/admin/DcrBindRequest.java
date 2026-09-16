/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.provisioning.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E11: bind a freshly-created OAuth client to a new registration_access_token (subscriber copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record DcrBindRequest(String realmId, String clientInternalId, String clientId) {
}
