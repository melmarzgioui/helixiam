/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow;

/**
 * Helix IAM E2: the recorded result of an execution that has already run. Absence from the
 * outcomes map means "not yet attempted".
 */
public enum ExecutionOutcome {
    SUCCEEDED,
    FAILED
}
