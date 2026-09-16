package group.mfnr.authorization.flow;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E2.4: the default post-password browser flow. Until per-realm flows are persisted
 * (E2.5) the flow is built in code: an OTP step is REQUIRED when the user has MFA enabled,
 * otherwise the (empty) flow completes immediately — preserving today's behaviour.
 */
class BrowserFlowsTest {

    @Test
    void mfaEnabled_requiresAnOtpStep() {
        AuthFlow flow = BrowserFlows.postPassword(true);

        assertThat(flow.executions()).hasSize(1);
        assertThat(flow.executions().get(0).authenticatorId()).isEqualTo("otp");
        assertThat(flow.executions().get(0).requirement()).isEqualTo(Requirement.REQUIRED);
    }

    @Test
    void mfaDisabled_isEmptyAndCompletesImmediately() {
        AuthFlow flow = BrowserFlows.postPassword(false);

        assertThat(flow.executions()).isEmpty();
        assertThat(new FlowEvaluator().evaluate(flow, Map.of()).kind()).isEqualTo(Decision.Kind.SUCCESS);
    }
}
