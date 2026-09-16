package io.helixiam.authorization.flow;

import io.helixiam.authorization.flow.persistence.AuthExecutionDefinition;
import io.helixiam.authorization.flow.persistence.AuthFlowDefinition;

import java.util.ArrayList;
import java.util.List;

/**
 * Helix IAM E2.4/E2.5: the default post-password browser flow in code. E2.5 normally loads the
 * flow from the per-realm store; this is the fallback used when the store has no flow (or is
 * unreachable), preserving today's behaviour exactly. Expressed as an {@link AuthFlowDefinition}
 * so the runtime maps and replays it identically to a stored flow.
 */
public final class BrowserFlows {

    public static final String OTP_EXECUTION_ID = "browser-otp";

    private BrowserFlows() {
    }

    /** The steps that run after the password factor: a REQUIRED OTP when MFA is enabled. */
    public static AuthFlow postPassword(final boolean mfaEnabled) {
        if (mfaEnabled) {
            return AuthFlow.of("browser-postpw",
                    AuthExecution.authenticator(OTP_EXECUTION_ID, "otp", Requirement.REQUIRED));
        }
        return AuthFlow.of("browser-postpw");
    }

    /** Same as {@link #postPassword} but as a flat definition (the no-store fallback for E2.5). */
    public static AuthFlowDefinition fallbackDefinition(final boolean mfaEnabled) {
        final List<AuthExecutionDefinition> executions = new ArrayList<>();
        if (mfaEnabled) {
            executions.add(new AuthExecutionDefinition(OTP_EXECUTION_ID, null, "otp", "REQUIRED", false, 10));
        }
        return new AuthFlowDefinition("browser", null, executions);
    }
}
