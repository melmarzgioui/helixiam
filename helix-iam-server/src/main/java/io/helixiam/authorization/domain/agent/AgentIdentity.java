/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.agent;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.util.Date;

/**
 * Helix IAM Agent (non-human identity / NHI): a first-class, accountable machine principal — an automation,
 * a service, or an AI agent — registered in a realm and owned by an accountable human. The agent is the
 * natural key ({@code realm_id} + {@code name}); it carries a lifecycle {@code status} (ACTIVE / SUSPENDED
 * / EXPIRED / REVOKED) and an {@code auth_method} describing how it authenticates (FEDERATED / SECRET /
 * JWT). When bound to an OIDC {@code client_id} the agent can obtain tokens through that client. This is
 * the registry record only — token issuance and claim enrichment are wired separately. No field is secret,
 * so nothing is encrypted at rest.
 */
@Entity
@Table(name = "agent_identity")
@EntityListeners(AuditingEntityListener.class)
public class AgentIdentity {

    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "realm_id", nullable = false)
    private String realmId;

    /** Realm-unique natural key (no spaces, treated like a client/credential name). */
    @Column(name = "name", nullable = false)
    private String name;

    /** Human-friendly label for the console. */
    @Column(name = "display_name")
    private String displayName;

    /** Free-text purpose of the agent. */
    @Column(name = "description")
    private String description;

    /** The accountable human (username or email) — never null. */
    @Column(name = "owner", nullable = false)
    private String owner;

    /** Lifecycle state: ACTIVE | SUSPENDED | EXPIRED | REVOKED (stored as the enum name). */
    @Column(name = "status", nullable = false)
    private String status = "ACTIVE";

    /** How the agent authenticates: FEDERATED | SECRET | JWT (stored as the enum name). */
    @Column(name = "auth_method", nullable = false)
    private String authMethod = "SECRET";

    /** The bound OIDC client used for token issuance (nullable, analogous to a WIF credential's clientId). */
    @Column(name = "client_id")
    private String clientId;

    /** CSV of scopes granted to the agent (nullable). */
    @Column(name = "scopes")
    private String scopes;

    /** CSV of the agent's OWN least-privilege realm roles (its standing authority; nullable). */
    @Column(name = "roles")
    private String roles;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Date createdAt;

    /** When the agent's authority lapses (nullable — no expiry). */
    @Column(name = "expires_at")
    private Date expiresAt;

    /** Last time the agent obtained a token (nullable until first use). */
    @Column(name = "last_used_at")
    private Date lastUsedAt;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    public String getId() { return id; }
    public void setId(final String id) { this.id = id; }
    public String getRealmId() { return realmId; }
    public void setRealmId(final String realmId) { this.realmId = realmId; }
    public String getName() { return name; }
    public void setName(final String name) { this.name = name; }
    public String getDisplayName() { return displayName; }
    public void setDisplayName(final String displayName) { this.displayName = displayName; }
    public String getDescription() { return description; }
    public void setDescription(final String description) { this.description = description; }
    public String getOwner() { return owner; }
    public void setOwner(final String owner) { this.owner = owner; }
    public String getStatus() { return status; }
    public void setStatus(final String status) { this.status = status; }
    public String getAuthMethod() { return authMethod; }
    public void setAuthMethod(final String authMethod) { this.authMethod = authMethod; }
    public String getClientId() { return clientId; }
    public void setClientId(final String clientId) { this.clientId = clientId; }
    public String getScopes() { return scopes; }
    public void setScopes(final String scopes) { this.scopes = scopes; }

    public String getRoles() { return roles; }
    public void setRoles(final String roles) { this.roles = roles; }
    public Date getCreatedAt() { return createdAt; }
    public void setCreatedAt(final Date createdAt) { this.createdAt = createdAt; }
    public Date getExpiresAt() { return expiresAt; }
    public void setExpiresAt(final Date expiresAt) { this.expiresAt = expiresAt; }
    public Date getLastUsedAt() { return lastUsedAt; }
    public void setLastUsedAt(final Date lastUsedAt) { this.lastUsedAt = lastUsedAt; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(final boolean enabled) { this.enabled = enabled; }
}
