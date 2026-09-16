/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.org.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/** Helix IAM Organizations: subscriber-side view of an organization (mirrors the publisher copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OrgDto(String realmId, String orgId, String name, String displayName, List<String> domains,
                     boolean enabled, long memberCount, Long createdAt) {
}
