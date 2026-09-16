package group.mfnr.authorization.flow;

/**
 * Helix IAM E2: how an execution participates in its parent flow (Keycloak semantics).
 */
public enum Requirement {
    /** Must succeed for the flow to succeed. */
    REQUIRED,
    /** One ALTERNATIVE in the flow must succeed (only evaluated when the flow has no REQUIRED). */
    ALTERNATIVE,
    /** A sub-flow that only runs when its conditions pass; otherwise skipped. */
    CONDITIONAL,
    /** Skipped entirely. */
    DISABLED
}
