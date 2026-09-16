package group.mfnr.authorization.domain.mfa;

import java.io.Serializable;

/**
 * Helix IAM E3.3: AMQP request to finish a WebAuthn registration (subscriber copy). Binary fields
 * are base64url strings; the publisher issues + holds the challenge.
 */
public class WebAuthnRegistration implements Serializable {

    private static final long serialVersionUID = 1L;

    private String userId;
    private String attestationObject;
    private String clientDataJSON;
    private String challenge;
    private String origin;
    private String rpId;

    public WebAuthnRegistration() {
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(final String userId) {
        this.userId = userId;
    }

    public String getAttestationObject() {
        return attestationObject;
    }

    public void setAttestationObject(final String attestationObject) {
        this.attestationObject = attestationObject;
    }

    public String getClientDataJSON() {
        return clientDataJSON;
    }

    public void setClientDataJSON(final String clientDataJSON) {
        this.clientDataJSON = clientDataJSON;
    }

    public String getChallenge() {
        return challenge;
    }

    public void setChallenge(final String challenge) {
        this.challenge = challenge;
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(final String origin) {
        this.origin = origin;
    }

    public String getRpId() {
        return rpId;
    }

    public void setRpId(final String rpId) {
        this.rpId = rpId;
    }
}
