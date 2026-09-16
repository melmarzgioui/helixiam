package group.mfnr.authorization.domain.mfa;

import io.helixiam.persistence.security.AttributeEncryption;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** Helix IAM E3.4: a user's HOTP credential — Base64 secret (encrypted at rest) + a counter. */
@Entity
@Table(name = "mfa_hotp")
public class HotpCredentialEntity {

    @Id
    @Column(name = "user_id")
    private String userId;

    @Convert(converter = AttributeEncryption.class)
    @Column(name = "secret")
    private String secret;

    @Column(name = "counter")
    private long counter;

    public HotpCredentialEntity() {
    }

    public HotpCredentialEntity(final String userId, final String secret, final long counter) {
        this.userId = userId;
        this.secret = secret;
        this.counter = counter;
    }

    public String getUserId() {
        return userId;
    }

    public String getSecret() {
        return secret;
    }

    public long getCounter() {
        return counter;
    }

    public void setCounter(final long counter) {
        this.counter = counter;
    }
}
