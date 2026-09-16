/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.realm;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;

import java.util.Date;

/**
 * Helix IAM E2.5: a per-realm authentication flow (header row). The ordered tree of steps lives
 * in {@link AuthFlowExecutionEntity}. {@code built_in} marks the seeded defaults the admin
 * console may copy but not delete.
 */
@Entity
@Table(name = "auth_flow")
public class AuthFlowEntity {

    @Id
    @Column(name = "flow_id")
    private String flowId;

    @Column(name = "realm_id")
    private String realmId;

    @Column(name = "alias")
    private String alias;

    @Column(name = "built_in")
    private boolean builtIn;

    @CreationTimestamp
    @Column(name = "creation_date", updatable = false)
    private Date creationDate;

    public AuthFlowEntity() {
    }

    public AuthFlowEntity(final String flowId, final String realmId, final String alias, final boolean builtIn) {
        this.flowId = flowId;
        this.realmId = realmId;
        this.alias = alias;
        this.builtIn = builtIn;
    }

    public String getFlowId() {
        return flowId;
    }

    public String getRealmId() {
        return realmId;
    }

    public String getAlias() {
        return alias;
    }

    public boolean isBuiltIn() {
        return builtIn;
    }

    /** Helix IAM (named flows): rename a non-built-in flow. */
    public void setAlias(final String alias) {
        this.alias = alias;
    }
}
