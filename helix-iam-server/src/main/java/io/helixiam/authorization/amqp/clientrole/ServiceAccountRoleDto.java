/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.clientrole;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM (Wave 4): a role granted to a client's service account (publisher copy); also the assign/unassign payload. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ServiceAccountRoleDto(String id, String realmId, String clientId, String roleName,
                                    String roleType, String roleClientId) {
}
