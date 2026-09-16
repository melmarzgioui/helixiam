package group.mfnr.authorization.domain.authz;

import jakarta.persistence.*;

/** Helix IAM (Wave 6): a named authorization scope on a resource server. */
@Entity @Table(name = "authz_scope")
public class AuthzScopeEntity {
    @Id @GeneratedValue(strategy = GenerationType.UUID) @Column(name = "id", updatable = false) private String id;
    @Column(name = "realm_id") private String realmId = "master";
    @Column(name = "client_id") private String clientId;
    @Column(name = "name") private String name;
    public String getId() { return id; } public void setId(String v) { this.id = v; }
    public String getRealmId() { return realmId; } public void setRealmId(String v) { this.realmId = v; }
    public String getClientId() { return clientId; } public void setClientId(String v) { this.clientId = v; }
    public String getName() { return name; } public void setName(String v) { this.name = v; }
}
