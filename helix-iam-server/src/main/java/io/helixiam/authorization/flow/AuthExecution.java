package io.helixiam.authorization.flow;

import java.util.Map;

/**
 * Helix IAM E2: one node in a flow tree — either a leaf that runs an authenticator (by its
 * SPI id) or a nested sub-flow — together with how it participates in its parent
 * ({@link Requirement}). Pure data so flows can be stored and edited from the admin console.
 */
public final class AuthExecution {

    private final String id;
    private final Requirement requirement;
    private final String authenticatorId; // non-null for a leaf
    private final AuthFlow subFlow;        // non-null for a sub-flow
    private final boolean condition;       // a condition gates a CONDITIONAL sub-flow
    private final Map<String, String> config; // per-execution admin config (from the flow editor)

    private AuthExecution(final String id, final Requirement requirement,
                          final String authenticatorId, final AuthFlow subFlow,
                          final boolean condition, final Map<String, String> config) {
        this.id = id;
        this.requirement = requirement;
        this.authenticatorId = authenticatorId;
        this.subFlow = subFlow;
        this.condition = condition;
        this.config = config == null ? Map.of() : Map.copyOf(config);
    }

    /** A leaf execution that runs the authenticator with the given SPI id. */
    public static AuthExecution authenticator(final String id, final String authenticatorId,
                                              final Requirement requirement) {
        return authenticator(id, authenticatorId, requirement, Map.of());
    }

    /** A leaf execution with per-execution admin config. */
    public static AuthExecution authenticator(final String id, final String authenticatorId,
                                              final Requirement requirement, final Map<String, String> config) {
        return new AuthExecution(id, requirement, authenticatorId, null, false, config);
    }

    /** A nested sub-flow participating in its parent with the given requirement. */
    public static AuthExecution subFlow(final String id, final Requirement requirement,
                                        final AuthFlow subFlow) {
        return new AuthExecution(id, requirement, null, subFlow, false, Map.of());
    }

    /**
     * A condition execution inside a CONDITIONAL sub-flow: its outcome decides whether the
     * sub-flow runs (SUCCEEDED = condition met → sub-flow active; FAILED = skip the sub-flow).
     */
    public static AuthExecution condition(final String id, final String authenticatorId) {
        return new AuthExecution(id, Requirement.REQUIRED, authenticatorId, null, true, Map.of());
    }

    public String id() {
        return id;
    }

    public Requirement requirement() {
        return requirement;
    }

    public String authenticatorId() {
        return authenticatorId;
    }

    public AuthFlow subFlow() {
        return subFlow;
    }

    public boolean isSubFlow() {
        return subFlow != null;
    }

    /** True when this execution gates a CONDITIONAL sub-flow (see {@link #condition}). */
    public boolean isCondition() {
        return condition;
    }

    /** The per-execution admin config (immutable; empty when none). */
    public Map<String, String> config() {
        return config;
    }
}
