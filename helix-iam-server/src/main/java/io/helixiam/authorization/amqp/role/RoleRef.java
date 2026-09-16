/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.role;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5-S2: realm role create request / reference (publisher-side copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RoleRef(String realmId, String roleId, String name) {
}
