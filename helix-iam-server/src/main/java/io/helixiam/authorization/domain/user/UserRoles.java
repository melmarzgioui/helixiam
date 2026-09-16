/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.user;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;

import java.io.Serializable;

@Entity
@Table(name = "user_roles")
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserRoles implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "role_id")
    @JsonProperty
    private String roleId;

    @JsonProperty
    @Column(name = "name")
    private String name;

    @JsonProperty
    @Column(name = "tenant_id")
    private String tenantId;

    /** A curated default/system role (admin, user, auditor) — protected from deletion in the admin API. */
    @JsonProperty
    @Column(name = "system_role")
    private boolean systemRole;

    /** The realm's default role — auto-assigned to every new user. At most one per realm. */
    @JsonProperty
    @Column(name = "default_role")
    private boolean defaultRole;

    public UserRoles() {
    }

    public UserRoles(final String name, final String tenantId) {
        this.name = name;
        this.tenantId = tenantId;
    }

    public UserRoles(final String name, final String tenantId, final boolean systemRole, final boolean defaultRole) {
        this.name = name;
        this.tenantId = tenantId;
        this.systemRole = systemRole;
        this.defaultRole = defaultRole;
    }

    /** Full constructor (roleId included) — used by config-as-code import mapping and tests. */
    public UserRoles(final String roleId, final String name, final String tenantId,
                     final boolean systemRole, final boolean defaultRole) {
        this.roleId = roleId;
        this.name = name;
        this.tenantId = tenantId;
        this.systemRole = systemRole;
        this.defaultRole = defaultRole;
    }

    public String getName() {
        return name;
    }

    public String getRoleId() {
        return roleId;
    }

    public String getTenantRoleName() {
        return name + "_" + tenantId;
    }

    public String getTenantId() {
        return tenantId;
    }

    public boolean isSystemRole() {
        return systemRole;
    }

    public void setSystemRole(final boolean systemRole) {
        this.systemRole = systemRole;
    }

    public boolean isDefaultRole() {
        return defaultRole;
    }

    public void setDefaultRole(final boolean defaultRole) {
        this.defaultRole = defaultRole;
    }
}
