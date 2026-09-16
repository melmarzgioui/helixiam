/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.adminrbac;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/** Helix IAM: resolve effective admin permissions for a principal holding {@code roleNames} (publisher copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AdminEffectivePermissionsRef(String realmId, List<String> roleNames) {
}
