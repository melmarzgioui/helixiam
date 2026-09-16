package group.mfnr.authorization.domain.credential;

import java.io.Serializable;

/** Helix IAM: AMQP request to verify a login credential of a given type (subscriber copy). */
public class CredentialVerification implements Serializable {

    private static final long serialVersionUID = 1L;

    private String type;
    private String userId;
    private String input;

    public CredentialVerification() {
    }

    public String getType() {
        return type;
    }

    public void setType(final String type) {
        this.type = type;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(final String userId) {
        this.userId = userId;
    }

    public String getInput() {
        return input;
    }

    public void setInput(final String input) {
        this.input = input;
    }
}
