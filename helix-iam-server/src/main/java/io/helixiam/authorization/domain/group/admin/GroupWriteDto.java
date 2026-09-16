/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.group.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5-S4: create/rename payload for a group (groupId null = create). Mirrors the publisher copy. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GroupWriteDto(String realmId, String groupId, String name, String parentId) {
}
