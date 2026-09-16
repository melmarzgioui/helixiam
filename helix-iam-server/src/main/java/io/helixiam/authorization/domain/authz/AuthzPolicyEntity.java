/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.authz;

import jakarta.persistence.*;

/** Helix IAM (Wave 6): a role-based policy (type ROLE; logic POSITIVE|NEGATIVE; csv role names). */
@Entity @Table(name = "authz_policy")
public class AuthzPolicyEntity {
    @Id @GeneratedValue(strategy = GenerationType.UUID) @Column(name = "id", updatable = false) private String id;
    @Column(name = "realm_id") private String realmId = "master";
    @Column(name = "client_id") private String clientId;
    @Column(name = "name") private String name;
    @Column(name = "type") private String type = "ROLE";
    @Column(name = "logic") private String logic = "POSITIVE";
    @Column(name = "roles") private String roles;
    public String getId() { return id; } public void setId(String v) { this.id = v; }
    public String getRealmId() { return realmId; } public void setRealmId(String v) { this.realmId = v; }
    public String getClientId() { return clientId; } public void setClientId(String v) { this.clientId = v; }
    public String getName() { return name; } public void setName(String v) { this.name = v; }
    public String getType() { return type; } public void setType(String v) { this.type = v; }
    public String getLogic() { return logic; } public void setLogic(String v) { this.logic = v; }
    public String getRoles() { return roles; } public void setRoles(String v) { this.roles = v; }
}
