/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.flow.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM (named flows): rename a non-built-in flow. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FlowRenameDto(String realmId, String alias, String newAlias) {
}
