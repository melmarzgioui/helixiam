package group.mfnr.authorization.amqp.mfa;

import java.io.Serializable;

/** Helix IAM E3.2: AMQP request to verify-and-consume a recovery code (publisher copy). */
public class RecoveryCodeVerification implements Serializable {

    private static final long serialVersionUID = 1L;

    private String userId;
    private String code;

    public RecoveryCodeVerification() {
    }

    public RecoveryCodeVerification(final String userId, final String code) {
        this.userId = userId;
        this.code = code;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(final String userId) {
        this.userId = userId;
    }

    public String getCode() {
        return code;
    }

    public void setCode(final String code) {
        this.code = code;
    }
}
