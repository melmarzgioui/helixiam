/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.group;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.util.UUID;

/** Helix IAM E8.5-S4: a realm role mapped onto a {@link UserGroup} (members inherit it). */
@Entity
@Table(name = "user_group_role")
public class UserGroupRole {

    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "group_id")
    private String groupId;

    @Column(name = "role_id")
    private String roleId;

    public UserGroupRole() {
    }

    public UserGroupRole(final String groupId, final String roleId) {
        this.id = UUID.randomUUID().toString();
        this.groupId = groupId;
        this.roleId = roleId;
    }

    public String getId() {
        return id;
    }

    public String getGroupId() {
        return groupId;
    }

    public String getRoleId() {
        return roleId;
    }
}
