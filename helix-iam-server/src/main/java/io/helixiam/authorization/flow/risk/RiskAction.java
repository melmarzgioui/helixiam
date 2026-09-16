package io.helixiam.authorization.flow.risk;

/**
 * Helix IAM (adaptive auth): what the realm policy does for a given risk band.
 * <ul>
 *   <li>{@link #ALLOW} — let the login through with no extra friction;</li>
 *   <li>{@link #STEP_UP} — require an additional factor (OTP/TOTP step-up) before completing;</li>
 *   <li>{@link #DENY} — reject the login.</li>
 * </ul>
 */
public enum RiskAction {
    ALLOW,
    STEP_UP,
    DENY;

    /** Lenient parse used when reading the policy from realm settings; unknown/blank → {@code ALLOW}. */
    public static RiskAction fromString(final String value) {
        if (value == null) {
            return ALLOW;
        }
        return switch (value.trim().toLowerCase()) {
            case "step_up", "step-up", "stepup", "challenge", "mfa" -> STEP_UP;
            case "deny", "block", "reject" -> DENY;
            default -> ALLOW;
        };
    }
}
