/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Serialises every key-state transition of one realm (activate, rotate, retire, attach, the first-use generation): a
 * PostgreSQL transaction-scoped advisory lock keyed by the realm, held until the surrounding transaction ends. Two
 * concurrent activations can therefore never leave two ACTIVE keys of one family. Must be called inside a transaction
 * (the JPA transaction shares its connection with this {@link JdbcTemplate}).
 */
@Component
public class RealmKeyLock {

    private final JdbcTemplate jdbc;

    public RealmKeyLock(final JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** Blocks until this transaction holds the realm's key lock. */
    public void lock(final String realmId) {
        jdbc.query("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", rs -> null, "helix.realm_key:" + realmId);
    }
}
