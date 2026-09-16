/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.agent;

/** A realm-scoped reference to an Agent (for get/delete/lifecycle ops by id within a realm). */
public record AgentIdentityRef(String realmId, String id) {
}
