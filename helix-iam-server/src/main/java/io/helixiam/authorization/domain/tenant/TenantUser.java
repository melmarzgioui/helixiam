/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.tenant;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.helixiam.authorization.domain.user.UserRoles;
import jakarta.persistence.*;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.util.*;

@Entity
@Table(name = "tenant_user")
@EntityListeners(AuditingEntityListener.class)
public class TenantUser {
    @Id
    @Column(name = "tenant_user_id")
    @GeneratedValue(strategy = GenerationType.UUID)
    @JsonProperty
    private String tenantUserId;

    @Column(name = "tenant_id")
    private String tenantId;
    @Column(name = "user_id")
    private String userId;

    // Round 6: the user's profile attributes used to be mapped here as an element collection joined on user_id. A user
    // has one tenant_user row per realm, so every membership of one user mapped the same collection (same key), and
    // Hibernate refused to flush a session holding two of them ("Found shared references to a collection"). Nothing
    // read it from here (profile attributes come from UserCredentials), so the mapping is gone.



    @JsonProperty
    @OneToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_in_role",
            joinColumns = {@JoinColumn(name = "tenant_user_id")},
            inverseJoinColumns = {@JoinColumn(name = "role_id")}
    )
    private List<UserRoles> roles = new ArrayList<>();

    public void setTenantId(final String tenantId) {
        this.tenantId = tenantId;
    }

    public void setUserId(final String userId) {
        this.userId = userId;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getUserId() {
        return userId;
    }

    public String getTenantUserId() {
        return tenantUserId;
    }

    public List<UserRoles> getRoles() {
        return roles;
    }
}
