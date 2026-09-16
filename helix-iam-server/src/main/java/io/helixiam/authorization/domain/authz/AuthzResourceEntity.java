/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.authz;

import jakarta.persistence.*;

/** Helix IAM (Wave 6): a protected resource (name + URIs + associated scope names, csv). */
@Entity @Table(name = "authz_resource")
public class AuthzResourceEntity {
    @Id @GeneratedValue(strategy = GenerationType.UUID) @Column(name = "id", updatable = false) private String id;
    @Column(name = "realm_id") private String realmId = "master";
    @Column(name = "client_id") private String clientId;
    @Column(name = "name") private String name;
    @Column(name = "uris") private String uris;
    @Column(name = "scopes") private String scopes;
    public String getId() { return id; } public void setId(String v) { this.id = v; }
    public String getRealmId() { return realmId; } public void setRealmId(String v) { this.realmId = v; }
    public String getClientId() { return clientId; } public void setClientId(String v) { this.clientId = v; }
    public String getName() { return name; } public void setName(String v) { this.name = v; }
    public String getUris() { return uris; } public void setUris(String v) { this.uris = v; }
    public String getScopes() { return scopes; } public void setScopes(String v) { this.scopes = v; }
}
