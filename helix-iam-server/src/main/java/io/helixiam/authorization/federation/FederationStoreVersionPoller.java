/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Production readiness item 1: keeps this replica's identity-provider registry in step with writes made on other
 * replicas. Every {@code helix.federation.store.poll-interval-seconds} (default 10, 0 = off) it asks the store for the
 * per-realm config versions ({@code idp_config_version}, one small query) and reloads the realms whose version moved
 * ({@link FederationStoreRefresher#refreshChanged()}). This works on every deployment, including the PostgreSQL-only
 * ({@code queue}) one, so a console write or a realm import reaches every replica within one interval, without a
 * restart and without Redis.
 *
 * <p>A failing poll is logged (a warning on the first failure, then quietly until it recovers) and retried at the next
 * interval; the replica keeps serving the providers it has.
 */
public class FederationStoreVersionPoller implements AutoCloseable {

    private static final Logger LOG = LogManager.getLogger(FederationStoreVersionPoller.class);

    private final FederationStoreRefresher refresher;
    private final Duration interval;
    private ScheduledExecutorService scheduler;
    private volatile boolean failing;

    public FederationStoreVersionPoller(final FederationStoreRefresher refresher, final Duration interval) {
        this.refresher = refresher;
        this.interval = interval;
    }

    /** Starts polling (no-op when the interval is zero or negative, or when already started). */
    public synchronized void start() {
        if (scheduler != null) {
            return;
        }
        if (interval.isZero() || interval.isNegative()) {
            LOG.info("Helix federation: identity-provider config polling is off; a write on another replica takes "
                    + "effect here at the next restart");
            return;
        }
        scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            final Thread thread = new Thread(runnable, "helix-idp-config-poll");
            thread.setDaemon(true);
            return thread;
        });
        final long millis = interval.toMillis();
        scheduler.scheduleWithFixedDelay(this::pollOnce, millis, millis, TimeUnit.MILLISECONDS);
        LOG.info("Helix federation: polling identity-provider config versions every {}", interval);
    }

    /** One poll: reloads the realms whose version moved. Never throws. Returns the number of realms reloaded. */
    public int pollOnce() {
        try {
            final int reloaded = refresher.refreshChanged();
            if (failing) {
                LOG.info("Helix federation: identity-provider config polling recovered");
                failing = false;
            }
            return reloaded;
        } catch (final RuntimeException e) {
            if (!failing) {
                LOG.warn("Helix federation: identity-provider config poll failed (retrying every {}): {}", interval,
                        e.getClass().getSimpleName());
                failing = true;
            } else {
                LOG.debug("Helix federation: identity-provider config poll still failing: {}",
                        e.getClass().getSimpleName());
            }
            return 0;
        }
    }

    @Override
    public synchronized void close() {
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
        }
    }
}
