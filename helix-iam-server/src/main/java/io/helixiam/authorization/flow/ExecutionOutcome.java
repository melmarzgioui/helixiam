package io.helixiam.authorization.flow;

/**
 * Helix IAM E2: the recorded result of an execution that has already run. Absence from the
 * outcomes map means "not yet attempted".
 */
public enum ExecutionOutcome {
    SUCCEEDED,
    FAILED
}
