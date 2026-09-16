/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.flow;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM (named flows): a realm flow in the editor's flow picker (mirrors the subscriber copy).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FlowSummaryDto(String realmId, String alias, boolean builtIn) {
}
