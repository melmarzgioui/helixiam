/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.agent;

/** Helix IAM Agent (NHI): realm-scoped reference to an agent (publisher copy). */
public record AgentIdentityRef(String realmId, String id) {
}
