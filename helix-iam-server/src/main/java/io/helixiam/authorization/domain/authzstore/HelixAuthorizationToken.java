/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.authzstore;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

/**
 * Helix IAM (Q1): the {@code findByToken} index — one row per code/access/refresh/id-token/state value of an
 * authorization, keyed by the SHA-256 hex of the value ({@code token_hash}) because raw token values are full
 * JWTs (too large for a btree key). Maps back to the owning {@link HelixAuthorization} id.
 */
@Entity
@Table(name = "helix_authorization_token",
        indexes = @Index(name = "helix_authorization_token_authz_idx", columnList = "authorization_id"))
public class HelixAuthorizationToken {

    @Id
    @Column(name = "token_hash", length = 64, updatable = false)
    private String tokenHash;

    @Column(name = "authorization_id")
    private String authorizationId;

    public String getTokenHash() { return tokenHash; }
    public void setTokenHash(final String tokenHash) { this.tokenHash = tokenHash; }
    public String getAuthorizationId() { return authorizationId; }
    public void setAuthorizationId(final String authorizationId) { this.authorizationId = authorizationId; }
}
