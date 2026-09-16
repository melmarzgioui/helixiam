/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.org.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM Organizations: identifies an organization, optionally with a target user and role within the
 * org (mirrors the publisher copy).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OrgRef(String realmId, String orgId, String userId, String role) {
}
