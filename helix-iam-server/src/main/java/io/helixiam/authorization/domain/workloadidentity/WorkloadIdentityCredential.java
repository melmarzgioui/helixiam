package io.helixiam.authorization.domain.workloadidentity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.util.Date;

/**
 * Helix IAM Workload Identity Federation (WIF): a trust policy that lets a workload — a Kubernetes pod,
 * a CI job, any process able to obtain an issuer-signed OIDC JWT — exchange that JWT for a Helix access
 * token with NO client secret. Modelled on the "federated identity credential" pattern: a credential
 * binds an external token's {@code (issuer, subject, audience)} to a Helix client identity, and the
 * exchange endpoint mints a realm-signed token for that identity after verifying the JWT against the
 * issuer's JWKS. None of these fields are secret, so nothing is encrypted at rest.
 */
@Entity
@Table(name = "workload_identity_credential")
@EntityListeners(AuditingEntityListener.class)
public class WorkloadIdentityCredential {

    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "realm_id", nullable = false)
    private String realmId;

    @Column(name = "name", nullable = false)
    private String name;

    /** Exact {@code iss} to trust (the external issuer URL, e.g. the cluster's OIDC issuer). */
    @Column(name = "issuer", nullable = false)
    private String issuer;

    /** Explicit JWKS URL; when null the JWKS is discovered from {@code issuer/.well-known/openid-configuration}. */
    @Column(name = "jwks_uri")
    private String jwksUri;

    /** Exact {@code sub} the presented JWT must carry (e.g. {@code system:serviceaccount:apps:billing}). */
    @Column(name = "subject", nullable = false)
    private String subject;

    /** Required {@code aud} the workload must request (e.g. {@code helix}). */
    @Column(name = "audience", nullable = false)
    private String audience;

    /** The Helix client identity the workload acts as (becomes the {@code sub} of the minted token). */
    @Column(name = "client_id", nullable = false)
    private String clientId;

    /** Space-delimited scopes granted to the minted token. */
    @Column(name = "scopes")
    private String scopes;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @CreationTimestamp
    @Column(name = "creation_date", updatable = false)
    private Date creationDate;

    public String getId() { return id; }
    public void setId(final String id) { this.id = id; }
    public String getRealmId() { return realmId; }
    public void setRealmId(final String realmId) { this.realmId = realmId; }
    public String getName() { return name; }
    public void setName(final String name) { this.name = name; }
    public String getIssuer() { return issuer; }
    public void setIssuer(final String issuer) { this.issuer = issuer; }
    public String getJwksUri() { return jwksUri; }
    public void setJwksUri(final String jwksUri) { this.jwksUri = jwksUri; }
    public String getSubject() { return subject; }
    public void setSubject(final String subject) { this.subject = subject; }
    public String getAudience() { return audience; }
    public void setAudience(final String audience) { this.audience = audience; }
    public String getClientId() { return clientId; }
    public void setClientId(final String clientId) { this.clientId = clientId; }
    public String getScopes() { return scopes; }
    public void setScopes(final String scopes) { this.scopes = scopes; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(final boolean enabled) { this.enabled = enabled; }
    public Date getCreationDate() { return creationDate; }
    public void setCreationDate(final Date creationDate) { this.creationDate = creationDate; }
}
