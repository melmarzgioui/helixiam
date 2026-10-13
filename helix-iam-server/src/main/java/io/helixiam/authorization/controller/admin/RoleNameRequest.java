/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/** Helix IAM E8.5-S2: create-realm-role request body. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RoleNameRequest(
        @NotBlank(message = "Role name is required.")
        // Reserved: "admin_<x>" would collide with the realm-admin authority of realm "<x>_<thisRealm>", and "FACTOR_"
        // is Spring Security 7's sign-in factor namespace (see RealmAdminAuthorities.isReservedRoleName).
        @Pattern(regexp = "(?is)(?!admin_)(?!factor_).*",
                message = "Role names starting with 'admin_' or 'FACTOR_' are reserved.")
        String name) {
}
