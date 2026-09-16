/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.device;

import io.helixiam.authorization.amqp.device.DeviceEnrollment;
import io.helixiam.authorization.amqp.device.DeviceEnrollmentPublisher;

import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * Helix IAM E4.1 (deferred): the mobile-facing device-enrollment flow. {@link #start} (called by the
 * logged-in user) mints a single-use ticket (id + attestation nonce) bound to that user; the web UI
 * shows it as a QR/deeplink. {@link #complete} (called by the phone) redeems the ticket and forwards
 * the device public key + platform attestation to the subscriber over AMQP — using the ticket's
 * bound user + nonce, never values from the redeeming request (so a phone can't enroll to another
 * account). The subscriber verifies the attestation and stores the credential (E4.1).
 */
public class DeviceEnrollmentService {

    private final DeviceEnrollmentTicketStore store;
    private final DeviceEnrollmentPublisher publisher;
    private final Supplier<String> tokenGenerator;
    private final LongSupplier clock;
    private final long ttlMillis;

    public DeviceEnrollmentService(final DeviceEnrollmentTicketStore store, final DeviceEnrollmentPublisher publisher,
                                   final Supplier<String> tokenGenerator, final LongSupplier clock,
                                   final long ttlMillis) {
        this.store = store;
        this.publisher = publisher;
        this.tokenGenerator = tokenGenerator;
        this.clock = clock;
        this.ttlMillis = ttlMillis;
    }

    /** Mints + stores a single-use enrollment ticket for the logged-in user. */
    public DeviceEnrollmentTicket start(final String userId) {
        final String id = tokenGenerator.get();
        final String nonce = tokenGenerator.get();
        final DeviceEnrollmentTicket ticket = new DeviceEnrollmentTicket(id, userId, nonce, clock.getAsLong(), ttlMillis);
        store.save(ticket);
        return ticket;
    }

    /**
     * Redeems the ticket and forwards the attestation to the subscriber. The enrolled user + nonce
     * come from the stored ticket — never the request — so the phone can only enroll for the user
     * who minted the ticket.
     */
    public boolean complete(final String ticketId, final String deviceId, final String publicKeyB64Url,
                            final String platform, final String attestationB64Url, final boolean biometric) {
        final DeviceEnrollmentTicket ticket = store.find(ticketId).orElse(null);
        if (ticket == null) {
            return false;
        }
        final String userId = ticket.claim(clock.getAsLong());
        if (userId == null) {
            return false;
        }
        store.save(ticket);
        return Boolean.TRUE.equals(publisher.enroll(new DeviceEnrollment(
                userId, deviceId, publicKeyB64Url, platform, attestationB64Url, ticket.nonce(), biometric)));
    }
}
