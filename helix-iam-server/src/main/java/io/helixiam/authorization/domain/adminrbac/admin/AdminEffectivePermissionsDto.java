/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.adminrbac.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Helix IAM: the effective admin permissions a principal has in a realm.
 * <p>
 * {@code modelConfigured} is {@code false} when the realm has NO admin-role→permission grants at all — the
 * default-safe state in which enforcement behaves exactly as today (any authenticated admin is allowed).
 * {@code permissions} are the {@link io.helixiam.authorization.domain.adminrbac.AdminPermission#key()} values.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AdminEffectivePermissionsDto(String realmId, boolean modelConfigured, List<String> permissions) {
}
