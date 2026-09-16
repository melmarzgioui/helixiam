/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.flow.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM (named flows): create a new named flow, optionally copying an existing flow's steps. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FlowCreateDto(String realmId, String alias, String copyFromAlias) {
}
