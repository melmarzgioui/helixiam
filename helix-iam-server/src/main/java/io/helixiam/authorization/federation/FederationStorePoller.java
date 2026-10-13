/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.common.log.LogSafe;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Every replica follows the identity-provider store: every {@code helix.federation.store.poll-seconds} (default 60,
 * {@code 0} = off) it reloads the realms whose stored connections changed since this replica loaded them
 * ({@link FederationStoreRefresher#refreshChanged}). A connection disabled, deleted or re-keyed through another replica,
 * or brought in by a realm import, so takes effect everywhere without a restart.
 */
public class FederationStorePoller {

    private static final Logger LOG = LogManager.getLogger(FederationStorePoller.class);

    private final FederationStoreRefresher refresher;
    private final long pollSeconds;
    private ScheduledExecutorService scheduler;

    public FederationStorePoller(final FederationStoreRefresher refresher, final long pollSeconds) {
        this.refresher = refresher;
        this.pollSeconds = pollSeconds;
    }

    @PostConstruct
    void start() {
        if (pollSeconds <= 0) {
            LOG.warn("helix.federation.store.poll-seconds is 0: identity-provider changes made through another replica "
                    + "or a realm import reach this replica only at its next restart");
            return;
        }
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            final Thread t = new Thread(r, "federation-store-poller");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleWithFixedDelay(this::poll, pollSeconds, pollSeconds, TimeUnit.SECONDS);
    }

    /** One poll; a failure is logged and retried at the next one. */
    void poll() {
        try {
            refresher.refreshChanged();
        } catch (final RuntimeException e) {
            LOG.warn("Identity-provider store poll failed (retried at the next poll): {}", LogSafe.sanitize(e.getMessage()));
        }
    }

    @PreDestroy
    void stop() {
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
    }
}
