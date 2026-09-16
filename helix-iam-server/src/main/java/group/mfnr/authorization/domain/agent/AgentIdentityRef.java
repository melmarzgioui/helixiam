package group.mfnr.authorization.domain.agent;

/** A realm-scoped reference to an Agent (for get/delete/lifecycle ops by id within a realm). */
public record AgentIdentityRef(String realmId, String id) {
}
