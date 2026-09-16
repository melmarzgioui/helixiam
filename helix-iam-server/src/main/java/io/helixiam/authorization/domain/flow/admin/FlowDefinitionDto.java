/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.flow.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Helix IAM E8.5-S4: a realm's authentication flow as the console edits it — the flow's alias, whether
 * it is built-in, and its flat list of executions (the console builds the tree from {@code parentId}).
 * Mirrors the publisher's {@code amqp.flow.FlowDefinitionDto}.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FlowDefinitionDto(String realmId, String alias, boolean builtIn, List<FlowExecutionDto> executions) {
}
