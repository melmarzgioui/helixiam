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

/** Helix IAM (Wave 4): a role defined ON a client (a client role), subscriber-owned. */
@Entity
@Table(name = "client_role")
public class ClientRoleEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "role_id", updatable = false)
    private String roleId;

    @Column(name = "realm_id")
    private String realmId = "master";

    @Column(name = "client_id")
    private String clientId;

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "creation_date", updatable = false)
    private Timestamp creationDate = new Timestamp(System.currentTimeMillis());

    public String getRoleId() { return roleId; }
    public void setRoleId(final String v) { this.roleId = v; }
    public String getRealmId() { return realmId; }
    public void setRealmId(final String v) { this.realmId = v; }
    public String getClientId() { return clientId; }
    public void setClientId(final String v) { this.clientId = v; }
    public String getName() { return name; }
    public void setName(final String v) { this.name = v; }
    public String getDescription() { return description; }
    public void setDescription(final String v) { this.description = v; }
}
