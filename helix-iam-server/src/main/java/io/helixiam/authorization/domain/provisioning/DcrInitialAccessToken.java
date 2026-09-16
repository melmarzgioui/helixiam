/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.provisioning;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.util.UUID;

/**
 * Helix IAM E11: an initial access token (RFC 7591 §1.2) that authorises a single anonymous Dynamic
 * Client Registration when the realm's DCR policy is GATED. Stored hashed; consumed (deleted) on use.
 */
@Entity
@Table(name = "dcr_initial_access_token")
public class DcrInitialAccessToken {

    @Id
    @Column(name = "token_id")
    private String tokenId;

    @Column(name = "realm_id")
    private String realmId;

    @Column(name = "token_hash")
    private String tokenHash;

    public DcrInitialAccessToken() {
    }

    public DcrInitialAccessToken(final String realmId, final String tokenHash) {
        this.tokenId = UUID.randomUUID().toString();
        this.realmId = realmId;
        this.tokenHash = tokenHash;
    }

    public String getTokenId() {
        return tokenId;
    }

    public void setTokenId(final String tokenId) {
        this.tokenId = tokenId;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(final String realmId) {
        this.realmId = realmId;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public void setTokenHash(final String tokenHash) {
        this.tokenHash = tokenHash;
    }
}
