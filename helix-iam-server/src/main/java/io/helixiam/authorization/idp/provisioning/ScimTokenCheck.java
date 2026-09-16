/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.provisioning;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E11: a SCIM bearer-token verification request (publisher copy). Reused for IAT consume. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ScimTokenCheck(String realmId, String token) {
}
