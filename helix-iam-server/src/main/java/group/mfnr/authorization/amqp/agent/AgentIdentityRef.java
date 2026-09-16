package group.mfnr.authorization.amqp.agent;

/** Helix IAM Agent (NHI): realm-scoped reference to an agent (publisher copy). */
public record AgentIdentityRef(String realmId, String id) {
}
