package io.helixiam.authorization.domain.authz;

import jakarta.persistence.*;

/** Helix IAM (Wave 6): a permission binding a resource/scope to policies (csv), combined by decision strategy. */
@Entity @Table(name = "authz_permission")
public class AuthzPermissionEntity {
    @Id @GeneratedValue(strategy = GenerationType.UUID) @Column(name = "id", updatable = false) private String id;
    @Column(name = "realm_id") private String realmId = "master";
    @Column(name = "client_id") private String clientId;
    @Column(name = "name") private String name;
    @Column(name = "type") private String type = "RESOURCE";
    @Column(name = "resource_name") private String resourceName;
    @Column(name = "scope_name") private String scopeName;
    @Column(name = "policies") private String policies;
    @Column(name = "decision_strategy") private String decisionStrategy = "UNANIMOUS";
    public String getId() { return id; } public void setId(String v) { this.id = v; }
    public String getRealmId() { return realmId; } public void setRealmId(String v) { this.realmId = v; }
    public String getClientId() { return clientId; } public void setClientId(String v) { this.clientId = v; }
    public String getName() { return name; } public void setName(String v) { this.name = v; }
    public String getType() { return type; } public void setType(String v) { this.type = v; }
    public String getResourceName() { return resourceName; } public void setResourceName(String v) { this.resourceName = v; }
    public String getScopeName() { return scopeName; } public void setScopeName(String v) { this.scopeName = v; }
    public String getPolicies() { return policies; } public void setPolicies(String v) { this.policies = v; }
    public String getDecisionStrategy() { return decisionStrategy; } public void setDecisionStrategy(String v) { this.decisionStrategy = v; }
}
