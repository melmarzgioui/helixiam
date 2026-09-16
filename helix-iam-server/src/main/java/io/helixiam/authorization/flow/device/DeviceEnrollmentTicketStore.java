/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.device;

import java.util.Optional;

/**
 * Helix IAM E4.1 (deferred): store for device-enrollment tickets, keyed by id. The browser mints a
 * ticket on one node and the phone redeems it (possibly on another), so a Redis-backed impl drops in
 * for scale; in-process {@link InMemoryDeviceEnrollmentTicketStore} is the default.
 */
public interface DeviceEnrollmentTicketStore {

    void save(DeviceEnrollmentTicket ticket);

    Optional<DeviceEnrollmentTicket> find(String id);

    void remove(String id);
}
