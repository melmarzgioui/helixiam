/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow;

import java.util.Map;

/**
 * Helix IAM E2.2: evaluates an {@link AuthFlow} against the outcomes recorded so far and
 * decides what happens next. Pure and stateless — see {@code FlowEvaluatorTest}.
 */
public class FlowEvaluator {

    public Decision evaluate(final AuthFlow flow, final Map<String, ExecutionOutcome> outcomes) {
        // REQUIRED governs the flow: when any execution is REQUIRED, ALTERNATIVEs are not
        // evaluated (Keycloak semantics). Every REQUIRED must succeed; the first un-attempted
        // one is run next, and any failure fails the whole flow.
        final boolean sequential = flow.executions().stream()
                .anyMatch(e -> e.requirement() == Requirement.REQUIRED
                        || e.requirement() == Requirement.CONDITIONAL);
        if (sequential) {
            for (final AuthExecution execution : flow.executions()) {
                if (execution.requirement() == Requirement.REQUIRED) {
                    final ExecutionOutcome outcome = outcomes.get(execution.id());
                    if (outcome == null) {
                        return Decision.run(execution.id());
                    }
                    if (outcome == ExecutionOutcome.FAILED) {
                        return Decision.failure();
                    }
                } else if (execution.requirement() == Requirement.CONDITIONAL) {
                    final Decision sub = evaluateConditional(execution.subFlow(), outcomes);
                    // RUN (a condition or a step-up authenticator to run) and FAILURE (an active
                    // step-up failed) propagate; SUCCESS means satisfied-or-skipped → continue.
                    if (sub.kind() != Decision.Kind.SUCCESS) {
                        return sub;
                    }
                }
                // ALTERNATIVE / DISABLED are not evaluated when a REQUIRED/CONDITIONAL governs.
            }
            return Decision.success();
        }

        // No REQUIRED: the ALTERNATIVEs form an "any one succeeds" group. Run them in order;
        // the first success wins, and the flow fails only once every alternative has failed.
        boolean anyAlternative = false;
        AuthExecution firstUnattempted = null;
        for (final AuthExecution execution : flow.executions()) {
            if (execution.requirement() != Requirement.ALTERNATIVE) {
                continue;
            }
            anyAlternative = true;
            final ExecutionOutcome outcome = outcomes.get(execution.id());
            if (outcome == ExecutionOutcome.SUCCEEDED) {
                return Decision.success();
            }
            if (outcome == null && firstUnattempted == null) {
                firstUnattempted = execution;
            }
        }
        if (!anyAlternative) {
            return Decision.success(); // nothing to require (e.g. all DISABLED)
        }
        if (firstUnattempted != null) {
            return Decision.run(firstUnattempted.id());
        }
        return Decision.failure();
    }

    /**
     * Evaluates a CONDITIONAL sub-flow. Its condition executions are checked first: an
     * un-evaluated condition is run; a failed condition means the gate is not met, so the whole
     * sub-flow is skipped ({@link Decision#success()} = contributes nothing). Once every
     * condition is met, the sub-flow's remaining executions are treated as REQUIRED.
     */
    private Decision evaluateConditional(final AuthFlow subFlow,
                                         final Map<String, ExecutionOutcome> outcomes) {
        for (final AuthExecution execution : subFlow.executions()) {
            if (!execution.isCondition()) {
                continue;
            }
            final ExecutionOutcome outcome = outcomes.get(execution.id());
            if (outcome == null) {
                return Decision.run(execution.id());
            }
            if (outcome == ExecutionOutcome.FAILED) {
                return Decision.success(); // condition not met → skip the sub-flow
            }
        }
        for (final AuthExecution execution : subFlow.executions()) {
            if (execution.isCondition() || execution.requirement() == Requirement.DISABLED) {
                continue;
            }
            final ExecutionOutcome outcome = outcomes.get(execution.id());
            if (outcome == null) {
                return Decision.run(execution.id());
            }
            if (outcome == ExecutionOutcome.FAILED) {
                return Decision.failure();
            }
        }
        return Decision.success();
    }
}
