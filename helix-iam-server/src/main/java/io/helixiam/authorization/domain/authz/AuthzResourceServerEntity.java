/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.authz;

import jakarta.persistence.*;

/** Helix IAM (Wave 6): a client acting as a resource server. */
@Entity @Table(name = "authz_resource_server")
public class AuthzResourceServerEntity {
    @Id @GeneratedValue(strategy = GenerationType.UUID) @Column(name = "id", updatable = false) private String id;
    @Column(name = "realm_id") private String realmId = "master";
    @Column(name = "client_id") private String clientId;
    @Column(name = "enabled") private Boolean enabled = true;
    @Column(name = "decision_strategy") private String decisionStrategy = "UNANIMOUS";
    public String getId() { return id; } public void setId(String v) { this.id = v; }
    public String getRealmId() { return realmId; } public void setRealmId(String v) { this.realmId = v; }
    public String getClientId() { return clientId; } public void setClientId(String v) { this.clientId = v; }
    public Boolean getEnabled() { return enabled; } public void setEnabled(Boolean v) { this.enabled = v; }
    public String getDecisionStrategy() { return decisionStrategy; } public void setDecisionStrategy(String v) { this.decisionStrategy = v; }
}
