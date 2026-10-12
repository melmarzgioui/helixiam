/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.startup;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Keeps the plaintext-read migration mode ({@code HELIX_DB_ENCRYPTION_MIGRATE_PLAINTEXT=true}) impossible to miss: an
 * ERROR-level banner at startup, repeated every hour for as long as the mode is on.
 */
@Component
public class PlaintextMigrationBanner {

    private static final Logger LOG = LogManager.getLogger(PlaintextMigrationBanner.class);

    private final boolean migrating;
    private final String until;
    private final ScheduledExecutorService scheduler;

    @Autowired
    public PlaintextMigrationBanner(@Value("${helix.security.db-encryption.migrate-plaintext:false}") final boolean migrating,
                                    @Value("${helix.security.db-encryption.migrate-until:}") final String until) {
        this(migrating, until, migrating ? Executors.newSingleThreadScheduledExecutor(r -> {
            final Thread t = new Thread(r, "plaintext-migration-banner");
            t.setDaemon(true);
            return t;
        }) : null);
    }

    PlaintextMigrationBanner(final boolean migrating, final String until, final ScheduledExecutorService scheduler) {
        this.migrating = migrating;
        this.until = until;
        this.scheduler = scheduler;
    }

    @PostConstruct
    void start() {
        if (migrating && scheduler != null) {
            scheduler.scheduleAtFixedRate(() -> LOG.error(banner(until)), 0L, 1L, TimeUnit.HOURS);
        }
    }

    @PreDestroy
    void stop() {
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
    }

    static String banner(final String until) {
        return "\n=====================================================================================\n"
                + "  HELIX_DB_ENCRYPTION_MIGRATE_PLAINTEXT=true — SECRET COLUMNS THAT CANNOT BE DECRYPTED ARE READ\n"
                + "  AS PLAINTEXT. This also hides a changed DB_ENCRYPTION key or a planted plaintext secret.\n"
                + "  Migration window ends: " + (until == null || until.isBlank() ? "(not set)" : until) + "\n"
                + "  Unset it as soon as the plaintext rows have been rewritten (encrypted on their next write).\n"
                + "=====================================================================================";
    }
}
