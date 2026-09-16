/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.authzstore.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/** Helix IAM (Q1): wire form of a stored authorization (subscriber copy). The {@code blob} is opaque here. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AuthorizationRecord(String id, String principalName, String grantType, String blob,
                                  List<String> tokenKeys, Long expiresAtEpochMilli) {
}
