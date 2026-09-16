package io.helixiam.authorization.domain.httpsession;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

/**
 * Helix IAM (Q3): the subscriber-owned HTTP login session (Spring Session) when sessions are routed through
 * the queue, so the publisher needs no datasource. {@code blob} is the opaque base64 of the serialized session
 * attributes (incl. the SecurityContext) — the subscriber never interprets it. Indexed by principal (for the
 * logout cascade) and expiry (for cleanup).
 */
@Entity
@Table(name = "helix_http_session", indexes = {
        @Index(name = "helix_http_session_principal_idx", columnList = "principal_name"),
        @Index(name = "helix_http_session_expiry_idx", columnList = "expiry_time")})
public class HelixHttpSession {

    @Id
    @Column(name = "session_id", length = 128, updatable = false)
    private String sessionId;

    @Column(name = "principal_name")
    private String principalName;

    @Column(name = "blob", length = 4_194_304)
    private String blob;

    @Column(name = "creation_time")
    private Long creationTime;

    @Column(name = "last_access_time")
    private Long lastAccessTime;

    @Column(name = "max_inactive_seconds")
    private Integer maxInactiveSeconds;

    @Column(name = "expiry_time")
    private Long expiryTime;

    public String getSessionId() { return sessionId; }
    public void setSessionId(final String sessionId) { this.sessionId = sessionId; }
    public String getPrincipalName() { return principalName; }
    public void setPrincipalName(final String principalName) { this.principalName = principalName; }
    public String getBlob() { return blob; }
    public void setBlob(final String blob) { this.blob = blob; }
    public Long getCreationTime() { return creationTime; }
    public void setCreationTime(final Long creationTime) { this.creationTime = creationTime; }
    public Long getLastAccessTime() { return lastAccessTime; }
    public void setLastAccessTime(final Long lastAccessTime) { this.lastAccessTime = lastAccessTime; }
    public Integer getMaxInactiveSeconds() { return maxInactiveSeconds; }
    public void setMaxInactiveSeconds(final Integer maxInactiveSeconds) { this.maxInactiveSeconds = maxInactiveSeconds; }
    public Long getExpiryTime() { return expiryTime; }
    public void setExpiryTime(final Long expiryTime) { this.expiryTime = expiryTime; }
}
