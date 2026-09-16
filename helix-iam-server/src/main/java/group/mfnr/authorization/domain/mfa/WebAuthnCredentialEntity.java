package group.mfnr.authorization.domain.mfa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;

import java.util.Date;

/** Helix IAM E3.3: a stored WebAuthn/FIDO2 (passkey) credential — public key material + counter. */
@Entity
@Table(name = "webauthn_credential")
public class WebAuthnCredentialEntity {

    @Id
    @Column(name = "credential_id")
    private String credentialId;

    @Column(name = "user_id")
    private String userId;

    @Column(name = "attested_credential")
    private String attestedCredential;

    @Column(name = "sign_count")
    private long signCount;

    @CreationTimestamp
    @Column(name = "creation_date", updatable = false)
    private Date creationDate;

    public WebAuthnCredentialEntity() {
    }

    public WebAuthnCredentialEntity(final String credentialId, final String userId,
                                    final String attestedCredential, final long signCount) {
        this.credentialId = credentialId;
        this.userId = userId;
        this.attestedCredential = attestedCredential;
        this.signCount = signCount;
    }

    public String getCredentialId() {
        return credentialId;
    }

    public String getUserId() {
        return userId;
    }

    public String getAttestedCredential() {
        return attestedCredential;
    }

    public long getSignCount() {
        return signCount;
    }

    public void setSignCount(final long signCount) {
        this.signCount = signCount;
    }

    public Date getCreationDate() {
        return creationDate;
    }
}
