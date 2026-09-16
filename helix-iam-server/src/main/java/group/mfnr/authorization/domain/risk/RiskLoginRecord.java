package group.mfnr.authorization.domain.risk;

import java.io.Serializable;

/**
 * Helix IAM (adaptive auth): AMQP request (subscriber copy) to record a successful login so the
 * device + IP become "known" for future risk evaluation. Upserts the remembered-device and
 * login-IP history rows for (realm, user).
 */
public class RiskLoginRecord implements Serializable {

    private static final long serialVersionUID = 1L;

    private String realmId;
    private String userId;
    private String fingerprint;
    private String ip;
    private String country;
    private String userAgent;

    public RiskLoginRecord() {
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(final String realmId) {
        this.realmId = realmId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(final String userId) {
        this.userId = userId;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(final String fingerprint) {
        this.fingerprint = fingerprint;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(final String ip) {
        this.ip = ip;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(final String country) {
        this.country = country;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(final String userAgent) {
        this.userAgent = userAgent;
    }
}
