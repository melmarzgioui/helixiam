package group.mfnr.authorization.domain.risk;

import java.io.Serializable;

/**
 * Helix IAM (adaptive auth): AMQP response (subscriber copy) — the resolved server-side signals
 * for one login attempt. The publisher's {@code RiskEvaluator} turns these into a numeric score:
 * <ul>
 *   <li>{@code knownDevice} — the fingerprint matches a remembered device for this user;</li>
 *   <li>{@code hasEnrolledDevices} — the user has at least one remembered device at all (so a
 *       brand-new account isn't penalised as if every device were unknown);</li>
 *   <li>{@code knownIp} — the IP has been used by a previous successful login;</li>
 *   <li>{@code hasLoginHistory} — the user has any prior login-IP history at all;</li>
 *   <li>{@code recentFailureCount} — the current brute-force counter (velocity);</li>
 *   <li>{@code newCountry} — best-effort impossible-travel: the country differs from every
 *       previously-seen country (only meaningful when {@code country} is non-blank).</li>
 * </ul>
 */
public class RiskSignals implements Serializable {

    private static final long serialVersionUID = 1L;

    private boolean knownDevice;
    private boolean hasEnrolledDevices;
    private boolean knownIp;
    private boolean hasLoginHistory;
    private int recentFailureCount;
    private boolean newCountry;

    public RiskSignals() {
    }

    public boolean isKnownDevice() {
        return knownDevice;
    }

    public void setKnownDevice(final boolean knownDevice) {
        this.knownDevice = knownDevice;
    }

    public boolean isHasEnrolledDevices() {
        return hasEnrolledDevices;
    }

    public void setHasEnrolledDevices(final boolean hasEnrolledDevices) {
        this.hasEnrolledDevices = hasEnrolledDevices;
    }

    public boolean isKnownIp() {
        return knownIp;
    }

    public void setKnownIp(final boolean knownIp) {
        this.knownIp = knownIp;
    }

    public boolean isHasLoginHistory() {
        return hasLoginHistory;
    }

    public void setHasLoginHistory(final boolean hasLoginHistory) {
        this.hasLoginHistory = hasLoginHistory;
    }

    public int getRecentFailureCount() {
        return recentFailureCount;
    }

    public void setRecentFailureCount(final int recentFailureCount) {
        this.recentFailureCount = recentFailureCount;
    }

    public boolean isNewCountry() {
        return newCountry;
    }

    public void setNewCountry(final boolean newCountry) {
        this.newCountry = newCountry;
    }
}
