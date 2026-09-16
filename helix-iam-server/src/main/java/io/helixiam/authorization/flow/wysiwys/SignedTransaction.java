/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.wysiwys;

/**
 * Helix IAM E4.4: a WYSIWYS transaction-signing request. Holds the canonical challenge (what the
 * device signs) + a single-use nonce + absolute expiry. Single-use, expiry-bounded state machine:
 * the device signature (verified separately) moves it PENDING→SIGNED, then {@link #consume()} hands
 * the authorized result to the RP exactly once. Pure (clock passed in) so it is fully unit-testable.
 */
public class SignedTransaction {

    public enum Status { PENDING, SIGNED, CONSUMED, EXPIRED }

    private final String id;
    private final String userId;
    private final String action;
    private final String canonicalChallenge;
    private final String nonce;
    private final long createdAt;
    private final long expiryEpochMillis;

    private Status status = Status.PENDING;

    public SignedTransaction(final String id, final String userId, final String action,
                             final String canonicalChallenge, final String nonce,
                             final long createdAt, final long expiryEpochMillis) {
        this.id = id;
        this.userId = userId;
        this.action = action;
        this.canonicalChallenge = canonicalChallenge;
        this.nonce = nonce;
        this.createdAt = createdAt;
        this.expiryEpochMillis = expiryEpochMillis;
    }

    public String id() {
        return id;
    }

    public String userId() {
        return userId;
    }

    public String action() {
        return action;
    }

    public String canonicalChallenge() {
        return canonicalChallenge;
    }

    public String nonce() {
        return nonce;
    }

    public Status status() {
        return status;
    }

    public boolean isExpired(final long now) {
        return now >= expiryEpochMillis;
    }

    /** Records a verified device signature: only a PENDING, non-expired request becomes SIGNED. */
    public boolean sign(final long now) {
        if (status != Status.PENDING) {
            return false;
        }
        if (isExpired(now)) {
            status = Status.EXPIRED;
            return false;
        }
        status = Status.SIGNED;
        return true;
    }

    /** Single-use: returns the authorizing user id once for a SIGNED request, then null. */
    public String consume() {
        if (status != Status.SIGNED) {
            return null;
        }
        status = Status.CONSUMED;
        return userId;
    }
}
