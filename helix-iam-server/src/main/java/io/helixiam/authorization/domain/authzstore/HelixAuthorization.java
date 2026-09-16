package io.helixiam.authorization.domain.authzstore;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Helix IAM (Q1): the subscriber-owned store of an OAuth2 authorization when the token store is routed through
 * the queue. {@code blob} is the opaque base64 the publisher (de)serializes — the subscriber never interprets
 * it. Token/code/state values are indexed in {@link HelixAuthorizationToken} (by hash) for {@code findByToken}.
 */
@Entity
@Table(name = "helix_authorization")
public class HelixAuthorization {

    @Id
    @Column(name = "id", updatable = false)
    private String id;

    @Column(name = "principal_name")
    private String principalName;

    @Column(name = "grant_type")
    private String grantType;

    @Column(name = "blob", length = 1_048_576)
    private String blob;

    /** Epoch-milli of the latest-expiring contained token (for cleanup); nullable. */
    @Column(name = "expires_at")
    private Long expiresAt;

    public String getId() { return id; }
    public void setId(final String id) { this.id = id; }
    public String getPrincipalName() { return principalName; }
    public void setPrincipalName(final String principalName) { this.principalName = principalName; }
    public String getGrantType() { return grantType; }
    public void setGrantType(final String grantType) { this.grantType = grantType; }
    public String getBlob() { return blob; }
    public void setBlob(final String blob) { this.blob = blob; }
    public Long getExpiresAt() { return expiresAt; }
    public void setExpiresAt(final Long expiresAt) { this.expiresAt = expiresAt; }
}
