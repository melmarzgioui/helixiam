package group.mfnr.authorization.amqp.risk;

import java.io.Serializable;

/**
 * Helix IAM (adaptive auth): AMQP response (publisher copy) — the resolved server-side signals
 * for one login attempt, scored by {@code RiskEvaluator}. See the subscriber copy for the
 * meaning of each field.
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
