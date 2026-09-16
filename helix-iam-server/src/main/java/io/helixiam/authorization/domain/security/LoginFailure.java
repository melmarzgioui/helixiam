/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.security;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

import java.time.Instant;

/**
 * Auth-hardening (feature 1): per-realm, per-user brute-force counter. One row tracks the running failed
 * password attempts for a user within a realm, the timestamp of the last failure (for the sliding window)
 * and, when the threshold is hit, the {@code lockedUntil} instant after which logins are permitted again.
 *
 * <p>Lives in its own table ({@code login_failure}) so it is cheap to read/write on the login hot path and
 * never touches the {@code user_credentials} admin-lock flag.
 */
@Entity
@Table(name = "login_failure",
        uniqueConstraints = @UniqueConstraint(name = "uq_login_failure_realm_user", columnNames = {"realm_id", "user_id"}))
public class LoginFailure {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false)
    private String id;

    @Column(name = "realm_id", nullable = false)
    private String realmId;

    @Column(name = "user_id", nullable = false)
    private String userId;

    @Column(name = "failure_count", nullable = false)
    private int failureCount;

    @Column(name = "last_failure")
    private Instant lastFailure;

    /** When set and in the future, the account is locked until this instant. */
    @Column(name = "locked_until")
    private Instant lockedUntil;

    public LoginFailure() {
    }

    public LoginFailure(final String realmId, final String userId) {
        this.realmId = realmId;
        this.userId = userId;
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

    public int getFailureCount() {
        return failureCount;
    }

    public void setFailureCount(final int failureCount) {
        this.failureCount = failureCount;
    }

    public Instant getLastFailure() {
        return lastFailure;
    }

    public void setLastFailure(final Instant lastFailure) {
        this.lastFailure = lastFailure;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public void setLockedUntil(final Instant lockedUntil) {
        this.lockedUntil = lockedUntil;
    }
}
