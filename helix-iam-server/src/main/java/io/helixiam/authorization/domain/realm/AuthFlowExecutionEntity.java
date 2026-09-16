/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.realm;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Helix IAM E2.5: one execution of an {@link AuthFlowEntity} — a leaf authenticator, a
 * condition, or a sub-flow node (a node with children). Nesting is by {@code parent_id};
 * ordering within a parent by {@code priority}.
 */
@Entity
@Table(name = "auth_flow_execution")
public class AuthFlowExecutionEntity {

    @Id
    @Column(name = "execution_id")
    private String executionId;

    @Column(name = "flow_id")
    private String flowId;

    @Column(name = "parent_id")
    private String parentId;

    @Column(name = "authenticator_id")
    private String authenticatorId;

    @Column(name = "requirement")
    private String requirement;

    @Column(name = "is_condition")
    private boolean condition;

    @Column(name = "priority")
    private int priority;

    /** Per-execution admin config (from the flow editor) as a JSON object string; null when none. */
    @Column(name = "config", columnDefinition = "text")
    private String config;

    public AuthFlowExecutionEntity() {
    }

    public AuthFlowExecutionEntity(final String executionId, final String flowId, final String parentId,
                                   final String authenticatorId, final String requirement,
                                   final boolean condition, final int priority) {
        this(executionId, flowId, parentId, authenticatorId, requirement, condition, priority, null);
    }

    public AuthFlowExecutionEntity(final String executionId, final String flowId, final String parentId,
                                   final String authenticatorId, final String requirement,
                                   final boolean condition, final int priority, final String config) {
        this.executionId = executionId;
        this.flowId = flowId;
        this.parentId = parentId;
        this.authenticatorId = authenticatorId;
        this.requirement = requirement;
        this.condition = condition;
        this.priority = priority;
        this.config = config;
    }

    public String getExecutionId() {
        return executionId;
    }

    public String getFlowId() {
        return flowId;
    }

    public String getParentId() {
        return parentId;
    }

    public String getAuthenticatorId() {
        return authenticatorId;
    }

    public String getRequirement() {
        return requirement;
    }

    public boolean isCondition() {
        return condition;
    }

    public int getPriority() {
        return priority;
    }

    public String getConfig() {
        return config;
    }

    public void setConfig(final String config) {
        this.config = config;
    }
}
