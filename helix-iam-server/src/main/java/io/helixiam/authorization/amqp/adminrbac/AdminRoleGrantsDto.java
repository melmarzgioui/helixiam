/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.adminrbac;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/** Helix IAM: a realm admin role + the admin-permission keys it grants (publisher copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AdminRoleGrantsDto(String realmId, String roleId, String roleName, List<String> permissions) {
}
