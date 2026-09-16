package io.helixiam.authorization.domain.mfa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;

import java.util.Date;

/** Helix IAM E3.2: one single-use MFA recovery code (hash only; burned when used). */
@Entity
@Table(name = "mfa_recovery_code")
public class RecoveryCodeEntity {

    @Id
    @Column(name = "code_id")
    private String codeId;

    @Column(name = "user_id")
    private String userId;

    @Column(name = "code_hash")
    private String codeHash;

    @Column(name = "used")
    private boolean used;

    @CreationTimestamp
    @Column(name = "creation_date", updatable = false)
    private Date creationDate;

    public RecoveryCodeEntity() {
    }

    public RecoveryCodeEntity(final String codeId, final String userId, final String codeHash) {
        this.codeId = codeId;
        this.userId = userId;
        this.codeHash = codeHash;
    }

    public String getCodeId() {
        return codeId;
    }

    public String getUserId() {
        return userId;
    }

    public String getCodeHash() {
        return codeHash;
    }

    public boolean isUsed() {
        return used;
    }

    public void setUsed(final boolean used) {
        this.used = used;
    }
}
