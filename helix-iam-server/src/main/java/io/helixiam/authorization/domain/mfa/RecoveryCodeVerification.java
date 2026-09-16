package io.helixiam.authorization.domain.mfa;

import java.io.Serializable;

/** Helix IAM E3.2: AMQP request to verify-and-consume a recovery code (subscriber copy). */
public class RecoveryCodeVerification implements Serializable {

    private static final long serialVersionUID = 1L;

    private String userId;
    private String code;

    public RecoveryCodeVerification() {
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
