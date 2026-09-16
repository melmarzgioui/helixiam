/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.support;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Helix IAM multi-tenant (MT-3): the realm + lookup key round-trip through one packed string payload.
 * (Moved from io.helixiam.authorization.amqp: RealmScopedKey moved to .support in the strip-RabbitMQ
 * migration — see VENDOR-MAP.md / ADAPTERS.md deviation #4 — this is a pure pack/split utility test,
 * not AMQP-coupled.)
 */
class RealmScopedKeyTest {

    @Test
    void packThenSplit_roundTrips() {
        final String packed = RealmScopedKey.pack("gov", "client-123");
        assertArrayEquals(new String[]{"gov", "client-123"}, RealmScopedKey.split(packed));
    }

    @Test
    void split_withoutSeparator_defaultsToMaster() {
        assertArrayEquals(new String[]{"master", "legacy-id"}, RealmScopedKey.split("legacy-id"));
    }

    @Test
    void pack_blankRealm_defaultsToMaster() {
        assertEquals("master", RealmScopedKey.split(RealmScopedKey.pack(null, "x"))[0]);
        assertEquals("master", RealmScopedKey.split(RealmScopedKey.pack("  ", "x"))[0]);
    }
}
