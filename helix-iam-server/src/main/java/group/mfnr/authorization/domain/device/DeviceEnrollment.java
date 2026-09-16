package group.mfnr.authorization.domain.device;

import java.io.Serializable;

/**
 * Helix IAM E4.1: AMQP request to enroll a device-factor credential (subscriber copy). Binary fields
 * ({@code publicKey} SPKI, {@code attestation}, {@code nonce}) are base64url strings; the publisher
 * issues + holds the enrollment nonce.
 */
public class DeviceEnrollment implements Serializable {

    private static final long serialVersionUID = 1L;

    private String userId;
    private String deviceId;
    private String publicKey;
    private String platform;
    private String attestation;
    private String nonce;
    private boolean biometric;

    public DeviceEnrollment() {
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(final String userId) {
        this.userId = userId;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(final String deviceId) {
        this.deviceId = deviceId;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(final String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPlatform() {
        return platform;
    }

    public void setPlatform(final String platform) {
        this.platform = platform;
    }

    public String getAttestation() {
        return attestation;
    }

    public void setAttestation(final String attestation) {
        this.attestation = attestation;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(final String nonce) {
        this.nonce = nonce;
    }

    public boolean isBiometric() {
        return biometric;
    }

    public void setBiometric(final boolean biometric) {
        this.biometric = biometric;
    }
}
