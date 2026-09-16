/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.user.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5: admin password reset for a realm user (subscriber-side copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record UserPasswordDto(String realmId, String userId, String newPassword) {
}
