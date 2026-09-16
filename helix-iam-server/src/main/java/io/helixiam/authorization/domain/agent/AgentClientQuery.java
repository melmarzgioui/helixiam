/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.agent;

/**
 * Helix IAM Agent (NHI): the lookup the token endpoint runs to discover whether an authenticating client
 * is an agent — {@code realmId} + the OIDC {@code clientId} the agent is bound to. Field order matches the
 * publisher copy (positional Jackson over AMQP).
 */
public record AgentClientQuery(String realmId, String clientId) {
}
