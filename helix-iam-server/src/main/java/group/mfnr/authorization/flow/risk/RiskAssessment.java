package group.mfnr.authorization.flow.risk;

import java.util.List;

/**
 * Helix IAM (adaptive auth): the outcome of scoring a login attempt — the numeric score (0..100),
 * the {@link RiskBand} it falls into under the realm policy, the {@link RiskAction} the policy
 * dictates, and the human-readable reasons that contributed (for audit / a risk-events view).
 */
public record RiskAssessment(int score, RiskBand band, RiskAction action, List<String> reasons) {

    public RiskAssessment {
        reasons = reasons == null ? List.of() : List.copyOf(reasons);
    }
}
