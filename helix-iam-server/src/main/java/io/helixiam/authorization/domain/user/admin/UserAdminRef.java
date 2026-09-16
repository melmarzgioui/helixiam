/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.user.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5: identifies a single realm user (subscriber-side copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record UserAdminRef(String realmId, String userId) {
}
