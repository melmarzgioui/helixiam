/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.persistence;

import java.io.Serializable;
import java.util.Map;

/**
 * Helix IAM E2.5: a flat, transport-friendly row of a persisted flow (one execution). The
 * subscriber owns these rows; the publisher receives them over AMQP and the mapper rebuilds
 * the {@link io.helixiam.authorization.flow.AuthFlow} tree from {@code parentId} links. Mutable
 * POJO with matching field names on both sides so JSON marshalling round-trips it.
 */
public class AuthExecutionDefinition implements Serializable {

    private static final long serialVersionUID = 1L;

    private String id;
    private String parentId;        // null => top-level execution of the flow
    private String authenticatorId; // null for a pure sub-flow node
    private String requirement;     // REQUIRED | ALTERNATIVE | CONDITIONAL | DISABLED
    private boolean condition;      // true => a condition gating a CONDITIONAL sub-flow
    private int priority;           // ordering within the parent
    private Map<String, String> config; // per-execution admin config (from the flow editor)

    public AuthExecutionDefinition() {
    }

    public AuthExecutionDefinition(final String id, final String parentId, final String authenticatorId,
                                   final String requirement, final boolean condition, final int priority) {
        this(id, parentId, authenticatorId, requirement, condition, priority, Map.of());
    }

    public AuthExecutionDefinition(final String id, final String parentId, final String authenticatorId,
                                   final String requirement, final boolean condition, final int priority,
                                   final Map<String, String> config) {
        this.id = id;
        this.parentId = parentId;
        this.authenticatorId = authenticatorId;
        this.requirement = requirement;
        this.condition = condition;
        this.priority = priority;
        this.config = config;
    }

    public String getId() {
        return id;
    }

    public void setId(final String id) {
        this.id = id;
    }

    public String getParentId() {
        return parentId;
    }

    public void setParentId(final String parentId) {
        this.parentId = parentId;
    }

    public String getAuthenticatorId() {
        return authenticatorId;
    }

    public void setAuthenticatorId(final String authenticatorId) {
        this.authenticatorId = authenticatorId;
    }

    public String getRequirement() {
        return requirement;
    }

    public void setRequirement(final String requirement) {
        this.requirement = requirement;
    }

    public boolean isCondition() {
        return condition;
    }

    public void setCondition(final boolean condition) {
        this.condition = condition;
    }

    public int getPriority() {
        return priority;
    }

    public void setPriority(final int priority) {
        this.priority = priority;
    }

    public Map<String, String> getConfig() {
        return config;
    }

    public void setConfig(final Map<String, String> config) {
        this.config = config;
    }
}
