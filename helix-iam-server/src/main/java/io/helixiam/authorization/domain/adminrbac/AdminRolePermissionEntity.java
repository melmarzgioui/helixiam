/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.adminrbac;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.sql.Timestamp;

/**
 * Helix IAM: one row = "this realm admin role grants this admin permission". Flat, subscriber-owned;
 * the role is a realm role ({@code user_roles.role_id}) and the permission is an {@link AdminPermission}
 * stored by enum {@code name()}. Realm-scoped via {@code realm_id} so a grant can't leak across realms.
 */
@Entity
@Table(name = "admin_role_permission")
public class AdminRolePermissionEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false)
    private String id;

    @Column(name = "realm_id")
    private String realmId = "master";

    @Column(name = "role_id")
    private String roleId;

    @Column(name = "permission")
    private String permission;

    @Column(name = "creation_date", updatable = false)
    private Timestamp creationDate = new Timestamp(System.currentTimeMillis());

    public String getId() { return id; }
    public void setId(final String v) { this.id = v; }
    public String getRealmId() { return realmId; }
    public void setRealmId(final String v) { this.realmId = v; }
    public String getRoleId() { return roleId; }
    public void setRoleId(final String v) { this.roleId = v; }
    public String getPermission() { return permission; }
    public void setPermission(final String v) { this.permission = v; }
}
