package io.helixiam.authorization.domain.realm;

import io.helixiam.persistence.security.AttributeEncryption;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.util.Date;

/**
 * A per-realm JWT signing key (Helix IAM E1.4).
 *
 * <p>The private key is stored Base64-encoded and <b>encrypted at rest</b> via
 * {@link AttributeEncryption}; the public key is plaintext. Keys move ACTIVE → ROTATED →
 * RETIRED: ACTIVE signs new tokens, ROTATED stays in the published JWKS so tokens signed
 * before rotation still verify (zero-downtime), RETIRED is dropped from the JWKS.
 */
@Entity
@Table(name = "realm_key")
@EntityListeners(AuditingEntityListener.class)
public class RealmKey {

    public enum Status { ACTIVE, ROTATED, RETIRED }

    @Id
    @Column(name = "key_id")
    private String keyId;

    @Column(name = "realm_id")
    private String realmId;

    @Column(name = "algorithm")
    private String algorithm = "RSA";

    @Column(name = "public_key")
    private String publicKey;

    @Convert(converter = AttributeEncryption.class)
    @Column(name = "private_key")
    private String privateKey;

    @Column(name = "status")
    private String status = Status.ACTIVE.name();

    @CreationTimestamp
    @Column(name = "creation_date", updatable = false)
    private Date creationDate;

    @Column(name = "rotated_date")
    private Date rotatedDate;

    public RealmKey() {
    }

    public RealmKey(final String keyId, final String realmId, final String algorithm,
                    final String publicKey, final String privateKey) {
        this.keyId = keyId;
        this.realmId = realmId;
        this.algorithm = algorithm;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.status = Status.ACTIVE.name();
    }

    public String getKeyId() {
        return keyId;
    }

    public String getRealmId() {
        return realmId;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(final Status status) {
        this.status = status.name();
    }

    public Date getCreationDate() {
        return creationDate;
    }

    public Date getRotatedDate() {
        return rotatedDate;
    }

    public void setRotatedDate(final Date rotatedDate) {
        this.rotatedDate = rotatedDate;
    }

    public boolean isActive() {
        return Status.ACTIVE.name().equals(status);
    }
}
