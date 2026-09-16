/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.scope;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5: create payload for a client scope (mirrors the subscriber copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ScopeWriteDto(String realmId, String name, String description) {
}
