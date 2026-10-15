/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Runs {@link TrustedListService} in the background on every replica: {@link TrustedListService#sync} every poll
 * interval (picks up refreshes and edits made elsewhere), and {@link TrustedListService#tick} every check interval
 * (refreshes what is due, under the lease, and records STALE/EXPIRED transitions). A zero interval turns that task off.
 */
public class TrustedListScheduler implements AutoCloseable {

    private static final Logger LOG = LogManager.getLogger(TrustedListScheduler.class);

    private final TrustedListService service;
    private final Duration poll;
    private final Duration check;
    private ScheduledExecutorService executor;

    public TrustedListScheduler(final TrustedListService service, final Duration poll, final Duration check) {
        this.service = service;
        this.poll = poll;
        this.check = check;
    }

    public synchronized void start() {
        if (executor != null) {
            return;
        }
        executor = Executors.newSingleThreadScheduledExecutor(r -> {
            final Thread t = new Thread(r, "helix-trusted-lists");
            t.setDaemon(true);
            return t;
        });
        if (!poll.isZero() && !poll.isNegative()) {
            executor.scheduleWithFixedDelay(this::sync, 0, poll.toMillis(), TimeUnit.MILLISECONDS);
        }
        if (!check.isZero() && !check.isNegative()) {
            executor.scheduleWithFixedDelay(service::tick, Math.min(check.toMillis(), 5_000), check.toMillis(),
                    TimeUnit.MILLISECONDS);
            LOG.info("Helix trusted lists: checking sources every {}, polling for changes every {}", check, poll);
        } else {
            LOG.info("Helix trusted lists: scheduled refresh is off (helix.wallet.trusted-lists.check-interval-seconds"
                    + "=0); sources refresh only from the console");
        }
    }

    private void sync() {
        try {
            service.sync();
        } catch (final RuntimeException e) {
            LOG.debug("Helix trusted lists: poll failed: {}", e.getClass().getSimpleName());
        }
    }

    @Override
    public synchronized void close() {
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }
    }
}
