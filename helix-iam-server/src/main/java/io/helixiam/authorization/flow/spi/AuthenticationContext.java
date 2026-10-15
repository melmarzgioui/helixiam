/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.spi;

import io.helixiam.authorization.flow.ExecutionOutcome;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Collections;

/**
 * Helix IAM E2.1: the mutable context an {@link Authenticator} drives during a single
 * execution. The authenticator inspects the realm/user, then calls exactly one of
 * {@link #success()}, {@link #failure(String)}, or {@link #challenge(String)}. The terminal
 * status maps to the flow engine's {@link ExecutionOutcome} via {@link #outcome()}.
 */
public class AuthenticationContext {

    public enum Status {ATTEMPTING, SUCCESS, FAILURE, CHALLENGE}

    /**
     * An execution attribute naming a realm-relative page ({@code /...}, never {@code //...}) that {@code GET /flow}
     * sends the browser to ONCE instead of rendering the challenge view (e.g. the EUDI wallet page of the wallet
     * verification step). It is removed when used, so coming back to {@code /flow} renders the view.
     */
    public static final String REDIRECT_ATTRIBUTE = "flow.redirect";

    /**
     * An execution attribute naming WHY the step failed, for its view to say so (e.g. {@code not_linked}); the
     * challenge view gets it as {@code flowFailure} when it is re-rendered after a failure.
     */
    public static final String FAILURE_ATTRIBUTE = "flow.failure";

    private final String executionId;
    private final String realmId;
    private String userId;

    private final Map<String, String> formData = new HashMap<>();
    private final Map<String, Object> attributes = new HashMap<>();
    /** Per-execution static configuration set by the admin in the flow editor (never mutated here). */
    private final Map<String, String> config;

    private Status status = Status.ATTEMPTING;
    private String message;
    private String challengeView;
    /** Verify-only wallet step: the level of assurance this step proved, applied only if it succeeds. */
    private String levelOfAssurance;
    /** Verify-only wallet step: the {@code verified_claims} JSON this step releases, applied only if it succeeds. */
    private String verifiedClaimsJson;

    public AuthenticationContext(final String executionId, final String realmId, final String userId) {
        this(executionId, realmId, userId, Map.of());
    }

    public AuthenticationContext(final String executionId, final String realmId, final String userId,
                                 final Map<String, String> config) {
        this.executionId = executionId;
        this.realmId = realmId;
        this.userId = userId;
        this.config = config == null ? Map.of() : Collections.unmodifiableMap(new HashMap<>(config));
    }

    /**
     * Records the user resolved by an identity-establishing step (e.g. the password
     * authenticator), for the rest of the flow to act on.
     */
    public void establishUser(final String userId) {
        this.userId = userId;
    }

    /** Supplies the parameters the user submitted in response to a challenge. */
    public void submit(final Map<String, String> parameters) {
        this.formData.putAll(parameters);
    }

    /** A submitted form parameter, or {@code null} if absent. */
    public String formParameter(final String name) {
        return formData.get(name);
    }

    /**
     * Stashes per-execution state that must survive the challenge→response round-trip (e.g. the
     * issued one-time-code challenge). The runtime persists these in the login session keyed by
     * this execution, and restores them before {@link Authenticator#action}.
     */
    public void putAttribute(final String key, final Object value) {
        attributes.put(key, value);
    }

    /** A previously {@link #putAttribute stashed} value for this execution, or {@code null}. */
    public Object getAttribute(final String key) {
        return attributes.get(key);
    }

    /** The full attribute bag — used by the runtime to persist/restore it. */
    public Map<String, Object> attributes() {
        return attributes;
    }

    /** A per-execution admin config value (from the flow editor), or {@code null} if unset. */
    public String config(final String key) {
        return config.get(key);
    }

    /** The full per-execution admin config map (immutable). */
    public Map<String, String> config() {
        return config;
    }

    /**
     * The level of assurance (an {@code acr} value, e.g. an eIDAS LoA URI) this step proves. The engine records it
     * for the login ({@code FlowExecutionState#pendingAcr}) only when the step SUCCEEDS; the login's {@code acr} then
     * becomes it when the flow completes.
     */
    public void assertLevelOfAssurance(final String acr) {
        this.levelOfAssurance = acr;
    }

    /** What {@link #assertLevelOfAssurance} recorded, or {@code null}. */
    public String assertedLevelOfAssurance() {
        return levelOfAssurance;
    }

    /**
     * The ID token {@code verified_claims} (a JSON object) this step releases; recorded for the login only when the
     * step SUCCEEDS, like {@link #assertLevelOfAssurance}.
     */
    public void releaseVerifiedClaims(final String json) {
        this.verifiedClaimsJson = json;
    }

    /** What {@link #releaseVerifiedClaims} recorded, or {@code null}. */
    public String releasedVerifiedClaims() {
        return verifiedClaimsJson;
    }

    public void success() {
        this.status = Status.SUCCESS;
    }

    public void failure(final String message) {
        this.status = Status.FAILURE;
        this.message = message;
    }

    public void challenge(final String view) {
        this.status = Status.CHALLENGE;
        this.challengeView = view;
    }

    public Status status() {
        return status;
    }

    public String message() {
        return message;
    }

    public String challengeView() {
        return challengeView;
    }

    public String executionId() {
        return executionId;
    }

    public String realmId() {
        return realmId;
    }

    public String userId() {
        return userId;
    }

    public Optional<ExecutionOutcome> outcome() {
        return switch (status) {
            case SUCCESS -> Optional.of(ExecutionOutcome.SUCCEEDED);
            case FAILURE -> Optional.of(ExecutionOutcome.FAILED);
            case ATTEMPTING, CHALLENGE -> Optional.empty();
        };
    }
}
