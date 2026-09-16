/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.role.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM E8.5-S2: subscriber-side view of a realm role (two-copy DTO; mirrors the publisher's
 * {@code amqp.role.RoleDto}). Roles are tenant(realm)-scoped via {@code user_roles}.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RoleDto(String realmId, String roleId, String name, boolean system, boolean defaultRole) {
}
