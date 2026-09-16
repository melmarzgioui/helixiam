package io.helixiam.authorization.amqp.risk;

import java.io.Serializable;

/**
 * Helix IAM (adaptive auth): AMQP request (publisher copy) carrying the raw login signals to the
 * subscriber, which resolves the device/IP history + brute-force counter. The {@code fingerprint}
 * is already a hash of the remembered-device cookie (the raw cookie never crosses the wire).
 */
public class RiskSignalRequest implements Serializable {

    private static final long serialVersionUID = 1L;

    private String realmId;
    private String userId;
    private String fingerprint;
    private String ip;
    private String country;

    public RiskSignalRequest() {
    }

    public RiskSignalRequest(final String realmId, final String userId, final String fingerprint,
                             final String ip, final String country) {
        this.realmId = realmId;
        this.userId = userId;
        this.fingerprint = fingerprint;
        this.ip = ip;
        this.country = country;
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
}
