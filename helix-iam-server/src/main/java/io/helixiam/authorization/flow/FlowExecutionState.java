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
    /**
     * Task 3 fix round 1: the brokered level of assurance a federated login asserted, held here (NOT in a
     * live {@code HELIX_ACR} session attribute) while this flow is mid-CHALLENGE, so it can never be read
     * by anything other than THIS flow completing. A fresh login always gets a brand-new {@code
     * FlowExecutionState} (see {@code FlowLoginSuccessHandler}/{@code FederatedLoginCompleter}), so an
     * abandoned challenge's pending acr can never leak into a later, unrelated login.
     */
    private String pendingAcr;
    /**
     * Task 18: work a federated login may only do once it has fully succeeded ({@code FederatedLoginCommit}), held
     * here while this flow is mid-CHALLENGE and made by {@code FlowController} when THIS flow completes.
     */
    private java.io.Serializable pendingCommit;
    /**
     * Final review F2: the marker a federated login reports its end with ({@code FederatedLoginOutcome}), held here
     * while this flow is mid-CHALLENGE and reported (then cleared) by {@code FlowController} when THIS flow ends.
     */
    private java.io.Serializable pendingOutcome;

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

    /** The brokered level of assurance pending promotion into {@code HELIX_ACR} when THIS flow completes. */
    public String pendingAcr() {
        return pendingAcr;
    }

    public void setPendingAcr(final String pendingAcr) {
        this.pendingAcr = pendingAcr;
    }

    /** The federated login's pending commit, made only when THIS flow completes ({@code FederatedLoginCommit}). */
    public java.io.Serializable pendingCommit() {
        return pendingCommit;
    }

    public void setPendingCommit(final java.io.Serializable pendingCommit) {
        this.pendingCommit = pendingCommit;
    }

    /** The federated login's outcome marker, reported once when THIS flow ends ({@code FederatedLoginOutcome}). */
    public java.io.Serializable pendingOutcome() {
        return pendingOutcome;
    }

    public void setPendingOutcome(final java.io.Serializable pendingOutcome) {
        this.pendingOutcome = pendingOutcome;
    }
}
