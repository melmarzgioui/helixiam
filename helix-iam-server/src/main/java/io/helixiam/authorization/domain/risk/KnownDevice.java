/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.risk;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

import java.time.Instant;

/**
 * Helix IAM (adaptive auth): a device the user has successfully authenticated from before, keyed
 * by a stable per-device fingerprint (a hashed remembered-device cookie value). One row per
 * (realm, user, fingerprint); {@code lastSeen} is refreshed on every successful login from the
 * device so a "known device" signal stays meaningful and stale devices can be aged out.
 *
 * <p>Flat-column JPA entity in its own {@code risk_known_device} table — read on the login hot
 * path and never touching {@code user_credentials} or {@code login_failure}.
 */
@Entity
@Table(name = "risk_known_device",
        uniqueConstraints = @UniqueConstraint(
                name = "uq_risk_known_device", columnNames = {"realm_id", "user_id", "fingerprint"}))
public class KnownDevice {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false)
    private String id;

    @Column(name = "realm_id", nullable = false)
    private String realmId;

    @Column(name = "user_id", nullable = false)
    private String userId;

    /** Hash of the remembered-device cookie value (never the raw cookie). */
    @Column(name = "fingerprint", nullable = false)
    private String fingerprint;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "first_seen")
    private Instant firstSeen;

    @Column(name = "last_seen")
    private Instant lastSeen;

    public KnownDevice() {
    }

    public KnownDevice(final String realmId, final String userId, final String fingerprint) {
        this.realmId = realmId;
        this.userId = userId;
        this.fingerprint = fingerprint;
    }

    public String getId() {
        return id;
    }

    public void setId(final String id) {
        this.id = id;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(final String realmId) {
        this.realmId = realmId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(final String userId) {
        this.userId = userId;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(final String fingerprint) {
        this.fingerprint = fingerprint;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(final String userAgent) {
        this.userAgent = userAgent;
    }

    public Instant getFirstSeen() {
        return firstSeen;
    }

    public void setFirstSeen(final Instant firstSeen) {
        this.firstSeen = firstSeen;
    }

    public Instant getLastSeen() {
        return lastSeen;
    }

    public void setLastSeen(final Instant lastSeen) {
        this.lastSeen = lastSeen;
    }
}
