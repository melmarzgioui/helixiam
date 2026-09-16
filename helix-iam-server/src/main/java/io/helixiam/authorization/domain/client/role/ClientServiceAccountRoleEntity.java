/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.client.role;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.sql.Timestamp;

/** Helix IAM (Wave 4): a role granted to a client's service account (the client_credentials identity). */
@Entity
@Table(name = "client_service_account_role")
public class ClientServiceAccountRoleEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false)
    private String id;

    @Column(name = "realm_id")
    private String realmId = "master";

    @Column(name = "client_id")
    private String clientId;

    @Column(name = "role_name")
    private String roleName;

    @Column(name = "role_type")
    private String roleType = "REALM";

    @Column(name = "role_client_id")
    private String roleClientId;

    @Column(name = "creation_date", updatable = false)
    private Timestamp creationDate = new Timestamp(System.currentTimeMillis());

    public String getId() { return id; }
    public void setId(final String v) { this.id = v; }
    public String getRealmId() { return realmId; }
    public void setRealmId(final String v) { this.realmId = v; }
    public String getClientId() { return clientId; }
    public void setClientId(final String v) { this.clientId = v; }
    public String getRoleName() { return roleName; }
    public void setRoleName(final String v) { this.roleName = v; }
    public String getRoleType() { return roleType; }
    public void setRoleType(final String v) { this.roleType = v; }
    public String getRoleClientId() { return roleClientId; }
    public void setRoleClientId(final String v) { this.roleClientId = v; }
}
