/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.federation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM B9: a (userId, idpAlias) reference for a user disconnecting one of their federated logins. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AccountUnlinkRef(String userId, String idpAlias) {
}
