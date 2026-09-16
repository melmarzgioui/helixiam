/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.adminrbac.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/** Helix IAM: resolve the effective admin permissions for a principal, given the realm role names it holds. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AdminEffectivePermissionsRef(String realmId, List<String> roleNames) {
}
