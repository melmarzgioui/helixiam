/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.push;

/**
 * Helix IAM E4.3: a push-approval ("approve on your phone") request with number matching. The
 * browser displays {@link #expectedNumber()}; the phone shows it among decoys and the user must tap
 * the match, which defeats reflexive approve taps (MFA fatigue). Single-use, TTL-bounded state
 * machine: the matching number APPROVES, a wrong number is an explicit DENY (treated as a fraud
 * signal), and {@link #consume()} is one-shot. The phone also signs {@link #challenge()} with its
 * device key (verified separately) to prove possession.
 *
 * Pure (clock passed in as {@code now} millis) so it is fully unit-testable.
 */
public class PushApproval {

    public enum Status { PENDING, APPROVED, DENIED, CONSUMED, EXPIRED }

    private final String id;
    private final String userId;
    private final int expectedNumber;
    private final String challenge;
    private final long createdAt;
    private final long ttlMillis;

    private Status status = Status.PENDING;

    public PushApproval(final String id, final String userId, final int expectedNumber,
                        final String challenge, final long createdAt, final long ttlMillis) {
        this.id = id;
        this.userId = userId;
        this.expectedNumber = expectedNumber;
        this.challenge = challenge;
        this.createdAt = createdAt;
        this.ttlMillis = ttlMillis;
    }

    public String id() {
        return id;
    }

    public String userId() {
        return userId;
    }

    public int expectedNumber() {
        return expectedNumber;
    }

    public String challenge() {
        return challenge;
    }

    public Status status() {
        return status;
    }

    public boolean isExpired(final long now) {
        return now - createdAt >= ttlMillis;
    }

    /**
     * The phone's response: only a PENDING, non-expired request matching {@link #expectedNumber()}
     * is APPROVED. A wrong number is recorded as a DENY (fatigue/fraud signal), not a silent retry.
     */
    public boolean approve(final int selectedNumber, final long now) {
        if (status != Status.PENDING) {
            return false;
        }
        if (isExpired(now)) {
            status = Status.EXPIRED;
            return false;
        }
        if (selectedNumber != expectedNumber) {
            status = Status.DENIED;
            return false;
        }
        status = Status.APPROVED;
        return true;
    }

    /** Explicit deny from the phone ("It wasn't me"). */
    public void deny() {
        if (status == Status.PENDING) {
            status = Status.DENIED;
        }
    }

    /** Single-use: returns the bound user id once for an APPROVED request, then null. */
    public String consume() {
        if (status != Status.APPROVED) {
            return null;
        }
        status = Status.CONSUMED;
        return userId;
    }
}
