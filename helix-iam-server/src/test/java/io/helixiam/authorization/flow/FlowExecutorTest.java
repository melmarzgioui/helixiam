package io.helixiam.authorization.flow;

import io.helixiam.authorization.flow.authenticators.OtpAuthenticator;
import io.helixiam.authorization.flow.authenticators.PasswordAuthenticator;
import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.Authenticator;
import io.helixiam.authorization.flow.spi.AuthenticatorMetadata;
import io.helixiam.authorization.flow.spi.AuthenticatorRegistry;
import io.helixiam.authorization.flow.spi.FactorClass;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E2.4: the FlowExecutor ties the engine, the authenticator registry and the
 * per-session state together — issuing challenges, processing submissions, auto-running
 * conditions, and completing/failing the flow. These tests exercise the whole loop with the
 * real password/OTP authenticators (behind their verifier seams) plus a fake condition.
 */
class FlowExecutorTest {

    private static final PasswordAuthenticator PASSWORD =
            new PasswordAuthenticator((u, p) -> u.equals("admin") && p.equals("pw")
                    ? Optional.of("user-1") : Optional.empty());
    private static final OtpAuthenticator OTP =
            new OtpAuthenticator((userId, code) -> code.equals("123456"));

    /** A condition that auto-succeeds without any user interaction (e.g. "risk is high"). */
    private static Authenticator riskCondition(final boolean met) {
        return new Authenticator() {
            @Override
            public AuthenticatorMetadata metadata() {
                return AuthenticatorMetadata.of("risk-high", "Risk is high", FactorClass.NONE, 0);
            }

            @Override
            public void authenticate(final AuthenticationContext context) {
                if (met) {
                    context.success();
                } else {
                    context.failure("risk low");
                }
            }
        };
    }

    private FlowExecutor executor(final Authenticator... extra) {
        final var all = new java.util.ArrayList<Authenticator>(List.of(PASSWORD, OTP));
        all.addAll(List.of(extra));
        return new FlowExecutor(new AuthenticatorRegistry(all), new FlowEvaluator());
    }

    /** A stateful step that stashes a value on challenge and reads it back on action (E3.1). */
    private static Authenticator stashingAuthenticator() {
        return new Authenticator() {
            @Override
            public AuthenticatorMetadata metadata() {
                return AuthenticatorMetadata.of("stash", "Stash", FactorClass.POSSESSION, 1);
            }

            @Override
            public void authenticate(final AuthenticationContext context) {
                context.putAttribute("secret", "42");
                context.challenge("stash-form");
            }

            @Override
            public void action(final AuthenticationContext context) {
                if ("42".equals(context.getAttribute("secret"))) {
                    context.success();
                } else {
                    context.failure("lost the challenge state");
                }
            }
        };
    }

    @Test
    void onChallenge_theCurrentViewIsRecordedInState_forGenericRendering() {
        FlowExecutor executor = executor();
        AuthFlow flow = AuthFlow.of("browser",
                AuthExecution.authenticator("e-otp", "otp", Requirement.REQUIRED));
        FlowExecutionState state = new FlowExecutionState("master");

        FlowProgress challenge = executor.begin(flow, state);

        assertThat(challenge.type()).isEqualTo(FlowProgress.Type.CHALLENGE);
        assertThat(state.currentChallengeView()).isEqualTo("otp-form");
        assertThat(state.currentChallengeExecutionId()).isEqualTo("e-otp");
    }

    @Test
    void challengeState_survivesTheChallengeToActionRoundTrip() {
        FlowExecutor executor = executor(stashingAuthenticator());
        AuthFlow flow = AuthFlow.of("browser",
                AuthExecution.authenticator("e-stash", "stash", Requirement.REQUIRED));
        FlowExecutionState state = new FlowExecutionState("master");

        FlowProgress challenge = executor.begin(flow, state);
        assertThat(challenge.type()).isEqualTo(FlowProgress.Type.CHALLENGE);

        // No payload submitted, but the value stashed during authenticate() must still be there.
        FlowProgress done = executor.submit(flow, state, "e-stash", Map.of());
        assertThat(done.type()).isEqualTo(FlowProgress.Type.COMPLETED);
    }

    @Test
    void passwordOnly_challengesThenCompletesOnValidCredentials() {
        FlowExecutor executor = executor();
        AuthFlow flow = AuthFlow.of("browser",
                AuthExecution.authenticator("e-pass", "password", Requirement.REQUIRED));
        FlowExecutionState state = new FlowExecutionState("master");

        FlowProgress first = executor.begin(flow, state);
        assertThat(first.type()).isEqualTo(FlowProgress.Type.CHALLENGE);
        assertThat(first.view()).isEqualTo("login-form");
        assertThat(first.executionId()).isEqualTo("e-pass");

        FlowProgress done = executor.submit(flow, state, "e-pass", Map.of("username", "admin", "password", "pw"));
        assertThat(done.type()).isEqualTo(FlowProgress.Type.COMPLETED);
        assertThat(done.userId()).isEqualTo("user-1");
    }

    @Test
    void passwordOnly_invalidCredentials_fails() {
        FlowExecutor executor = executor();
        AuthFlow flow = AuthFlow.of("browser",
                AuthExecution.authenticator("e-pass", "password", Requirement.REQUIRED));
        FlowExecutionState state = new FlowExecutionState("master");
        executor.begin(flow, state);

        FlowProgress result = executor.submit(flow, state, "e-pass", Map.of("username", "admin", "password", "nope"));

        assertThat(result.type()).isEqualTo(FlowProgress.Type.FAILED);
    }

    @Test
    void passwordThenOtp_completesAfterBothSteps() {
        FlowExecutor executor = executor();
        AuthFlow flow = AuthFlow.of("browser",
                AuthExecution.authenticator("e-pass", "password", Requirement.REQUIRED),
                AuthExecution.authenticator("e-otp", "otp", Requirement.REQUIRED));
        FlowExecutionState state = new FlowExecutionState("master");

        executor.begin(flow, state);
        FlowProgress afterPassword = executor.submit(flow, state, "e-pass", Map.of("username", "admin", "password", "pw"));
        assertThat(afterPassword.type()).isEqualTo(FlowProgress.Type.CHALLENGE);
        assertThat(afterPassword.view()).isEqualTo("otp-form");
        assertThat(afterPassword.executionId()).isEqualTo("e-otp");

        FlowProgress done = executor.submit(flow, state, "e-otp", Map.of("code", "123456"));
        assertThat(done.type()).isEqualTo(FlowProgress.Type.COMPLETED);
        assertThat(done.userId()).isEqualTo("user-1");
    }

    @Test
    void conditionalStepUp_whenConditionMet_runsTheOtpStep() {
        FlowExecutor executor = executor(riskCondition(true));
        AuthFlow flow = AuthFlow.of("browser",
                AuthExecution.authenticator("e-pass", "password", Requirement.REQUIRED),
                AuthExecution.subFlow("e-stepup", Requirement.CONDITIONAL,
                        AuthFlow.of("stepup",
                                AuthExecution.condition("c-risk", "risk-high"),
                                AuthExecution.authenticator("e-otp", "otp", Requirement.REQUIRED))));
        FlowExecutionState state = new FlowExecutionState("master");

        executor.begin(flow, state);
        // password submitted → condition auto-evaluates (met) → OTP step is now challenged
        FlowProgress afterPassword = executor.submit(flow, state, "e-pass", Map.of("username", "admin", "password", "pw"));

        assertThat(afterPassword.type()).isEqualTo(FlowProgress.Type.CHALLENGE);
        assertThat(afterPassword.view()).isEqualTo("otp-form");
    }

    @Test
    void conditionalStepUp_whenConditionNotMet_completesWithoutOtp() {
        FlowExecutor executor = executor(riskCondition(false));
        AuthFlow flow = AuthFlow.of("browser",
                AuthExecution.authenticator("e-pass", "password", Requirement.REQUIRED),
                AuthExecution.subFlow("e-stepup", Requirement.CONDITIONAL,
                        AuthFlow.of("stepup",
                                AuthExecution.condition("c-risk", "risk-high"),
                                AuthExecution.authenticator("e-otp", "otp", Requirement.REQUIRED))));
        FlowExecutionState state = new FlowExecutionState("master");

        executor.begin(flow, state);
        FlowProgress afterPassword = executor.submit(flow, state, "e-pass", Map.of("username", "admin", "password", "pw"));

        assertThat(afterPassword.type()).isEqualTo(FlowProgress.Type.COMPLETED);
        assertThat(afterPassword.userId()).isEqualTo("user-1");
    }
}
