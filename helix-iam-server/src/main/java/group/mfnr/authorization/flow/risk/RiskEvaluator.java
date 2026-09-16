package group.mfnr.authorization.flow.risk;

import group.mfnr.authorization.amqp.risk.RiskSignals;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Helix IAM (adaptive auth): the risk-scoring engine. Pure and side-effect free (see
 * {@code RiskEvaluatorTest}) — it turns the server-side {@link RiskSignals} resolved by the
 * subscriber into a 0..100 {@code score}, bands it under the realm {@link RiskPolicy}, and
 * resolves the policy {@link RiskAction}. No I/O, no clock, no Spring — trivially unit-testable.
 *
 * <h2>Signals &amp; weights</h2>
 * <ul>
 *   <li><b>New / unknown device</b> (+35): the remembered-device fingerprint matches no enrolled
 *       device for this user. Suppressed when the user has no enrolled devices at all (a brand-new
 *       account isn't penalised for having no history yet).</li>
 *   <li><b>New / unknown IP</b> (+25): the IP has not been seen on a prior successful login.
 *       Suppressed when the user has no login-IP history yet.</li>
 *   <li><b>Failed-attempt velocity</b> (+15 per recent failure, capped at +45): reuses the
 *       {@code login_failure} counter.</li>
 *   <li><b>Impossible-travel / new country</b> (+25, best-effort): the geo-resolved country has
 *       never been seen for this user. Degrades gracefully to no contribution when no geo source
 *       is available (country blank → signal is false).</li>
 * </ul>
 * The score is clamped to 0..100.
 */
@Component
public class RiskEvaluator {

    static final int WEIGHT_NEW_DEVICE = 35;
    static final int WEIGHT_NEW_IP = 25;
    static final int WEIGHT_PER_FAILURE = 15;
    static final int MAX_FAILURE_CONTRIBUTION = 45;
    static final int WEIGHT_NEW_COUNTRY = 25;

    /** Scores the signals and resolves the band + action under the given policy. */
    public RiskAssessment evaluate(final RiskSignals signals, final RiskPolicy policy) {
        final List<String> reasons = new ArrayList<>();
        int score = 0;

        // New device: only counts once the user has at least one remembered device.
        if (signals.isHasEnrolledDevices() && !signals.isKnownDevice()) {
            score += WEIGHT_NEW_DEVICE;
            reasons.add("New or unrecognised device");
        }

        // New IP: only counts once the user has prior login history.
        if (signals.isHasLoginHistory() && !signals.isKnownIp()) {
            score += WEIGHT_NEW_IP;
            reasons.add("New or unrecognised IP address");
        }

        // Failed-attempt velocity.
        final int failures = Math.max(0, signals.getRecentFailureCount());
        if (failures > 0) {
            final int contribution = Math.min(MAX_FAILURE_CONTRIBUTION, failures * WEIGHT_PER_FAILURE);
            score += contribution;
            reasons.add(failures + " recent failed login attempt" + (failures == 1 ? "" : "s"));
        }

        // Impossible-travel / new country (best-effort; false when no geo source).
        if (signals.isNewCountry()) {
            score += WEIGHT_NEW_COUNTRY;
            reasons.add("Login from a new country");
        }

        score = Math.max(0, Math.min(100, score));

        final RiskBand band = policy.band(score);
        final RiskAction action = policy.actionFor(band);
        return new RiskAssessment(score, band, action, reasons);
    }
}
