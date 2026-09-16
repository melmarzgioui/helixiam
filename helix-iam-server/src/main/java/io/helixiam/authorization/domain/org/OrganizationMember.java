/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.org;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.util.UUID;

/** Helix IAM Organizations: a user's membership in an {@link Organization}, with a role within the org. */
@Entity
@Table(name = "organization_member")
public class OrganizationMember {

    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "org_id")
    private String orgId;

    @Column(name = "user_id")
    private String userId;

    /** Role within the organization — e.g. {@code "member"} or {@code "admin"}. */
    @Column(name = "role")
    private String role;

    public OrganizationMember() {
    }

    public OrganizationMember(final String orgId, final String userId, final String role) {
        this.id = UUID.randomUUID().toString();
        this.orgId = orgId;
        this.userId = userId;
        this.role = role;
    }

    public String getId() {
        return id;
    }

    public String getOrgId() {
        return orgId;
    }

    public String getUserId() {
        return userId;
    }

    public String getRole() {
        return role;
    }

    public void setRole(final String role) {
        this.role = role;
    }
}
