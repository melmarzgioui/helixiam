/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 * Helix IAM E2.4: the per-login mutable state of a flow in progress — the realm, the outcomes
 * recorded so far (what the engine evaluates), the user once an identity step establishes it,
 * and the execution currently awaiting a user response. Serializable so it can live in the
 * (JDBC/Redis) HTTP session across challenge round-trips.
 */
public class FlowExecutionState implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String realmId;
    private final Map<String, ExecutionOutcome> outcomes = new HashMap<>();
    private final Map<String, Map<String, Object>> executionAttributes = new HashMap<>();
    private String userId;
    private String currentChallengeExecutionId;
    private String currentChallengeView;

    public FlowExecutionState(final String realmId) {
        this.realmId = realmId;
    }

    public String realmId() {
        return realmId;
    }

    public Map<String, ExecutionOutcome> outcomes() {
        return outcomes;
    }

    /**
     * Per-execution attribute bag (e.g. an issued one-time-code challenge) that must persist
     * across the challenge→response round-trip. Created on first access.
     */
    public Map<String, Object> attributesFor(final String executionId) {
        return executionAttributes.computeIfAbsent(executionId, k -> new HashMap<>());
    }

    public String userId() {
        return userId;
    }

    public void setUserId(final String userId) {
        this.userId = userId;
    }

    public String currentChallengeExecutionId() {
        return currentChallengeExecutionId;
    }

    public void setCurrentChallengeExecutionId(final String executionId) {
        this.currentChallengeExecutionId = executionId;
    }

    /** The view name the current authenticator asked to render — used to render any plugin screen. */
    public String currentChallengeView() {
        return currentChallengeView;
    }

    public void setCurrentChallengeView(final String view) {
        this.currentChallengeView = view;
    }
}
