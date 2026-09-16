/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.gdpr;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.util.Date;
import java.util.UUID;

/**
 * Helix IAM GDPR Art. 7: one immutable consent-ledger row — a per-user, per-client grant of a set of scopes,
 * later stamped with a withdrawal time rather than deleted (so the consent history survives for audit).
 * Scopes are stored as a comma-joined string in {@code scopes} to avoid a join table.
 */
@Entity
@Table(name = "consent_ledger")
public class ConsentLedgerEntity {

    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "realm_id")
    private String realmId;

    @Column(name = "user_id")
    private String userId;

    @Column(name = "client_id")
    private String clientId;

    /** Comma-joined scope names; never null (empty string == no scopes). */
    @Column(name = "scopes")
    private String scopes;

    @Column(name = "granted_at")
    private Date grantedAt;

    /** Null while the consent is active; set when it is withdrawn. */
    @Column(name = "withdrawn_at")
    private Date withdrawnAt;

    public ConsentLedgerEntity() {
    }

    public ConsentLedgerEntity(final String realmId, final String userId, final String clientId, final String scopes) {
        this.id = UUID.randomUUID().toString();
        this.realmId = realmId;
        this.userId = userId;
        this.clientId = clientId;
        this.scopes = scopes == null ? "" : scopes;
        this.grantedAt = new Date();
        this.withdrawnAt = null;
    }

    public String getId() {
        return id;
    }

    public String getRealmId() {
        return realmId;
    }

    public String getUserId() {
        return userId;
    }

    public String getClientId() {
        return clientId;
    }

    public String getScopes() {
        return scopes;
    }

    public Date getGrantedAt() {
        return grantedAt;
    }

    public Date getWithdrawnAt() {
        return withdrawnAt;
    }

    public void setWithdrawnAt(final Date withdrawnAt) {
        this.withdrawnAt = withdrawnAt;
    }
}
