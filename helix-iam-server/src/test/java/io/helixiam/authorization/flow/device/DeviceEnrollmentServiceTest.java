/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.device;

import io.helixiam.authorization.amqp.device.DeviceEnrollment;
import io.helixiam.authorization.amqp.device.DeviceEnrollmentPublisher;
import org.junit.jupiter.api.Test;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E4.1 (deferred): DeviceEnrollmentService issues a ticket for the logged-in user, then on
 * the phone's redemption forwards the attestation to the subscriber over AMQP — using the ticket's
 * bound user and nonce, never values supplied by the redeeming phone.
 */
class DeviceEnrollmentServiceTest {

    private static final long TTL = 300_000L;

    private final InMemoryDeviceEnrollmentTicketStore store = new InMemoryDeviceEnrollmentTicketStore();
    private final Deque<String> tokens = new ArrayDeque<>();
    private final AtomicReference<DeviceEnrollment> sent = new AtomicReference<>();
    private final DeviceEnrollmentPublisher publisher = enrollment -> {
        sent.set(enrollment);
        return true;
    };

    private DeviceEnrollmentService service() {
        return new DeviceEnrollmentService(store, publisher, tokens::removeFirst, () -> 0L, TTL);
    }

    @Test
    void start_mintsAPendingTicketBoundToTheUser() {
        tokens.add("ticket-1");
        tokens.add("nonce-1");
        final DeviceEnrollmentTicket t = service().start("user-7");

        assertThat(t.id()).isEqualTo("ticket-1");
        assertThat(t.userId()).isEqualTo("user-7");
        assertThat(t.nonce()).isEqualTo("nonce-1");
        assertThat(store.find("ticket-1")).isPresent();
    }

    @Test
    void complete_forwardsEnrollmentWithTheTicketsUserAndNonce() {
        tokens.add("ticket-1");
        tokens.add("nonce-1");
        final DeviceEnrollmentService service = service();
        service.start("user-7");

        final boolean ok = service.complete("ticket-1", "device-1", "spki-b64url", "apple-app-attest",
                "attestation-b64url", true);

        assertThat(ok).isTrue();
        assertThat(sent.get().getUserId()).isEqualTo("user-7");     // from the ticket, not the request
        assertThat(sent.get().getNonce()).isEqualTo("nonce-1");     // the ticket's attestation nonce
        assertThat(sent.get().getDeviceId()).isEqualTo("device-1");
        assertThat(sent.get().getPlatform()).isEqualTo("apple-app-attest");
        assertThat(sent.get().isBiometric()).isTrue();
    }

    @Test
    void complete_isSingleUse() {
        tokens.add("ticket-1");
        tokens.add("nonce-1");
        final DeviceEnrollmentService service = service();
        service.start("user-7");

        assertThat(service.complete("ticket-1", "d", "k", "none", "a", false)).isTrue();
        assertThat(service.complete("ticket-1", "d", "k", "none", "a", false)).isFalse(); // ticket spent
    }

    @Test
    void complete_rejectsAnUnknownTicket() {
        assertThat(service().complete("ghost", "d", "k", "none", "a", false)).isFalse();
    }
}
