package io.helixiam.authorization.flow;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E2.2: the flow engine is a pure function of (flow definition, outcomes so far)
 * → next decision. These tests pin the requirement semantics
 * (REQUIRED / ALTERNATIVE / CONDITIONAL / DISABLED) without any Spring or HTTP.
 */
class FlowEvaluatorTest {

    private final FlowEvaluator evaluator = new FlowEvaluator();

    @Test
    void singleRequiredExecution_notYetAttempted_runsThatAuthenticator() {
        AuthFlow flow = AuthFlow.of("browser",
                AuthExecution.authenticator("e-pass", "password", Requirement.REQUIRED));

        Decision decision = evaluator.evaluate(flow, Map.of());

        assertThat(decision.kind()).isEqualTo(Decision.Kind.RUN);
        assertThat(decision.executionId()).isEqualTo("e-pass");
    }

    @Test
    void requiredExecution_failed_failsTheFlow() {
        AuthFlow flow = AuthFlow.of("browser",
                AuthExecution.authenticator("e-pass", "password", Requirement.REQUIRED));

        Decision decision = evaluator.evaluate(flow, Map.of("e-pass", ExecutionOutcome.FAILED));

        assertThat(decision.kind()).isEqualTo(Decision.Kind.FAILURE);
    }

    @Test
    void requiredExecution_succeeded_succeedsTheFlow() {
        AuthFlow flow = AuthFlow.of("browser",
                AuthExecution.authenticator("e-pass", "password", Requirement.REQUIRED));

        Decision decision = evaluator.evaluate(flow, Map.of("e-pass", ExecutionOutcome.SUCCEEDED));

        assertThat(decision.kind()).isEqualTo(Decision.Kind.SUCCESS);
    }

    @Test
    void multipleRequired_runsThemInOrderThenSucceeds() {
        AuthFlow flow = AuthFlow.of("browser",
                AuthExecution.authenticator("e-pass", "password", Requirement.REQUIRED),
                AuthExecution.authenticator("e-otp", "otp", Requirement.REQUIRED));

        // password done, otp not yet → run otp
        Decision afterPassword = evaluator.evaluate(flow, Map.of("e-pass", ExecutionOutcome.SUCCEEDED));
        assertThat(afterPassword.kind()).isEqualTo(Decision.Kind.RUN);
        assertThat(afterPassword.executionId()).isEqualTo("e-otp");

        // both done → success
        Decision afterBoth = evaluator.evaluate(flow,
                Map.of("e-pass", ExecutionOutcome.SUCCEEDED, "e-otp", ExecutionOutcome.SUCCEEDED));
        assertThat(afterBoth.kind()).isEqualTo(Decision.Kind.SUCCESS);
    }

    private static AuthFlow twoAlternatives() {
        return AuthFlow.of("browser",
                AuthExecution.authenticator("e-passkey", "passkey", Requirement.ALTERNATIVE),
                AuthExecution.authenticator("e-deviceqr", "device-qr", Requirement.ALTERNATIVE));
    }

    @Test
    void alternatives_noneAttempted_runsTheFirst() {
        Decision decision = evaluator.evaluate(twoAlternatives(), Map.of());

        assertThat(decision.kind()).isEqualTo(Decision.Kind.RUN);
        assertThat(decision.executionId()).isEqualTo("e-passkey");
    }

    @Test
    void alternatives_oneSucceeded_succeedsTheFlow() {
        Decision decision = evaluator.evaluate(twoAlternatives(),
                Map.of("e-passkey", ExecutionOutcome.SUCCEEDED));

        assertThat(decision.kind()).isEqualTo(Decision.Kind.SUCCESS);
    }

    @Test
    void alternatives_firstFailed_runsTheNext() {
        Decision decision = evaluator.evaluate(twoAlternatives(),
                Map.of("e-passkey", ExecutionOutcome.FAILED));

        assertThat(decision.kind()).isEqualTo(Decision.Kind.RUN);
        assertThat(decision.executionId()).isEqualTo("e-deviceqr");
    }

    @Test
    void alternatives_allFailed_failsTheFlow() {
        Decision decision = evaluator.evaluate(twoAlternatives(),
                Map.of("e-passkey", ExecutionOutcome.FAILED, "e-deviceqr", ExecutionOutcome.FAILED));

        assertThat(decision.kind()).isEqualTo(Decision.Kind.FAILURE);
    }

    @Test
    void disabledExecution_isSkipped() {
        AuthFlow flow = AuthFlow.of("browser",
                AuthExecution.authenticator("e-pass", "password", Requirement.REQUIRED),
                AuthExecution.authenticator("e-legacy", "legacy", Requirement.DISABLED));

        Decision decision = evaluator.evaluate(flow, Map.of("e-pass", ExecutionOutcome.SUCCEEDED));

        assertThat(decision.kind()).isEqualTo(Decision.Kind.SUCCESS);
    }

    @Test
    void requiredPresent_alternativesAreNotEvaluated() {
        AuthFlow flow = AuthFlow.of("browser",
                AuthExecution.authenticator("e-pass", "password", Requirement.REQUIRED),
                AuthExecution.authenticator("e-passkey", "passkey", Requirement.ALTERNATIVE));

        // password succeeded; the alternative is never run when a REQUIRED governs the flow
        Decision decision = evaluator.evaluate(flow, Map.of("e-pass", ExecutionOutcome.SUCCEEDED));

        assertThat(decision.kind()).isEqualTo(Decision.Kind.SUCCESS);
    }

    /** browser flow: password REQUIRED, then a CONDITIONAL step-up sub-flow gated by a risk
     *  condition — if risk is high, OTP becomes required. */
    private static AuthFlow conditionalStepUpFlow() {
        return AuthFlow.of("browser",
                AuthExecution.authenticator("e-pass", "password", Requirement.REQUIRED),
                AuthExecution.subFlow("e-stepup", Requirement.CONDITIONAL,
                        AuthFlow.of("stepup",
                                AuthExecution.condition("c-risk", "risk-high"),
                                AuthExecution.authenticator("e-otp", "otp", Requirement.REQUIRED))));
    }

    @Test
    void conditional_conditionNotYetEvaluated_runsTheCondition() {
        Decision decision = evaluator.evaluate(conditionalStepUpFlow(),
                Map.of("e-pass", ExecutionOutcome.SUCCEEDED));

        assertThat(decision.kind()).isEqualTo(Decision.Kind.RUN);
        assertThat(decision.executionId()).isEqualTo("c-risk");
    }

    @Test
    void conditional_conditionMet_runsTheSubflowContent() {
        Decision decision = evaluator.evaluate(conditionalStepUpFlow(),
                Map.of("e-pass", ExecutionOutcome.SUCCEEDED, "c-risk", ExecutionOutcome.SUCCEEDED));

        assertThat(decision.kind()).isEqualTo(Decision.Kind.RUN);
        assertThat(decision.executionId()).isEqualTo("e-otp");
    }

    @Test
    void conditional_conditionNotMet_skipsTheSubflowAndSucceeds() {
        Decision decision = evaluator.evaluate(conditionalStepUpFlow(),
                Map.of("e-pass", ExecutionOutcome.SUCCEEDED, "c-risk", ExecutionOutcome.FAILED));

        assertThat(decision.kind()).isEqualTo(Decision.Kind.SUCCESS);
    }

    @Test
    void conditional_conditionMetButStepUpNotDone_isNotYetComplete() {
        Decision decision = evaluator.evaluate(conditionalStepUpFlow(),
                Map.of("e-pass", ExecutionOutcome.SUCCEEDED, "c-risk", ExecutionOutcome.SUCCEEDED,
                        "e-otp", ExecutionOutcome.SUCCEEDED));

        assertThat(decision.kind()).isEqualTo(Decision.Kind.SUCCESS);
    }
}
