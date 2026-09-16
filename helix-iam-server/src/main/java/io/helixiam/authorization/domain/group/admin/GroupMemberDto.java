/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.group.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5-S4: a member of a group — the user's id and username. Mirrors the publisher copy. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GroupMemberDto(String userId, String username) {
}
