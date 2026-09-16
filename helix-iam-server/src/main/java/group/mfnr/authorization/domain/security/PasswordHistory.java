package group.mfnr.authorization.domain.security;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;

/**
 * Auth-hardening (feature 3): a prior password hash for a user, retained so the password-policy
 * {@code historyCount} rule can reject reuse of a recent password. Stores only the Argon2id hash, never
 * the raw value; rows older than the realm's window are pruned by the enforcer.
 */
@Entity
@Table(name = "password_history")
public class PasswordHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false)
    private String id;

    @Column(name = "user_id", nullable = false)
    private String userId;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @CreationTimestamp
    @Column(name = "creation_date", updatable = false)
    private Instant creationDate;

    public PasswordHistory() {
    }

    public PasswordHistory(final String userId, final String passwordHash) {
        this.userId = userId;
        this.passwordHash = passwordHash;
    }

    public String getId() {
        return id;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(final String userId) {
        this.userId = userId;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(final String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public Instant getCreationDate() {
        return creationDate;
    }
}
