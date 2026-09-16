package io.helixiam.authorization.amqp.agent;

/**
 * Helix IAM Agent (NHI): the lookup the token customizer runs to discover whether an authenticating client
 * is an agent — {@code realmId} + the OIDC {@code clientId} the agent is bound to. Field order matches the
 * subscriber copy (positional Jackson over AMQP).
 */
public record AgentClientQuery(String realmId, String clientId) {
}
