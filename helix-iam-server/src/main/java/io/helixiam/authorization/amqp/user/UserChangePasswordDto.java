/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.user;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM (6) Self-service Account: a user changing <em>their own</em> password — the current password
 * must be supplied and verified before the new one is set (publisher copy; mirrors the subscriber's
 * {@code domain.user.admin.UserChangePasswordDto}).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record UserChangePasswordDto(String realmId, String userId, String currentPassword, String newPassword) {
}
