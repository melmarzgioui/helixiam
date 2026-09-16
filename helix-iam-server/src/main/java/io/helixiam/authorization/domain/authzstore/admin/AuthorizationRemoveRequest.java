/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.authzstore.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/** Helix IAM (Q1): remove an authorization by id, dropping its token-index entries (subscriber copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AuthorizationRemoveRequest(String id, List<String> tokenKeys) {
}
