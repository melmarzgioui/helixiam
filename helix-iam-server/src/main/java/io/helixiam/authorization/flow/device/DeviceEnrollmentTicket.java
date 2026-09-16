/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.device;

/**
 * Helix IAM E4.1 (deferred): a short-lived, single-use device-enrollment ticket. The logged-in user
 * mints it; the phone presents it to enroll. The ticket binds the user server-side (so the phone
 * cannot enroll to an arbitrary account) and carries the attestation nonce the device signs over.
 * Pure (clock passed in) so it is fully unit-testable.
 */
public class DeviceEnrollmentTicket {

    public enum Status { PENDING, USED, EXPIRED }

    private final String id;
    private final String userId;
    private final String nonce;
    private final long createdAt;
    private final long ttlMillis;

    private Status status = Status.PENDING;

    public DeviceEnrollmentTicket(final String id, final String userId, final String nonce,
                                  final long createdAt, final long ttlMillis) {
        this.id = id;
        this.userId = userId;
        this.nonce = nonce;
        this.createdAt = createdAt;
        this.ttlMillis = ttlMillis;
    }

    public String id() {
        return id;
    }

    public String userId() {
        return userId;
    }

    public String nonce() {
        return nonce;
    }

    public Status status() {
        return status;
    }

    public boolean isExpired(final long now) {
        return now - createdAt >= ttlMillis;
    }

    /** Single-use: returns the bound user id once for a PENDING, non-expired ticket, then null. */
    public String claim(final long now) {
        if (status != Status.PENDING) {
            return null;
        }
        if (isExpired(now)) {
            status = Status.EXPIRED;
            return null;
        }
        status = Status.USED;
        return userId;
    }
}
