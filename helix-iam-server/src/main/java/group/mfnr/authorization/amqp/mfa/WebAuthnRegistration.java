package group.mfnr.authorization.amqp.mfa;

import java.io.Serializable;

/** Helix IAM E3.3: AMQP request to finish a WebAuthn registration (publisher copy). */
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

    public WebAuthnRegistration(final String userId, final String attestationObject, final String clientDataJSON,
                                final String challenge, final String origin, final String rpId) {
        this.userId = userId;
        this.attestationObject = attestationObject;
        this.clientDataJSON = clientDataJSON;
        this.challenge = challenge;
        this.origin = origin;
        this.rpId = rpId;
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
