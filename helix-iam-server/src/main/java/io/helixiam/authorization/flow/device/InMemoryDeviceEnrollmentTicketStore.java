/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.device;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Helix IAM E4.1 (deferred): default in-process {@link DeviceEnrollmentTicketStore} (single-instance
 * / dev). A Redis-backed store replaces it for horizontal scale (@ConditionalOnMissingBean in FlowConfig).
 * Tickets are short-lived and single-use, so growth is bounded.
 */
public class InMemoryDeviceEnrollmentTicketStore implements DeviceEnrollmentTicketStore {

    private final ConcurrentMap<String, DeviceEnrollmentTicket> tickets = new ConcurrentHashMap<>();

    @Override
    public void save(final DeviceEnrollmentTicket ticket) {
        tickets.put(ticket.id(), ticket);
    }

    @Override
    public Optional<DeviceEnrollmentTicket> find(final String id) {
        return Optional.ofNullable(tickets.get(id));
    }

    @Override
    public void remove(final String id) {
        tickets.remove(id);
    }
}
