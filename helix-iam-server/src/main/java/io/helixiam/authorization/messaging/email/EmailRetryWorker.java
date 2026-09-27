/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.context.SmartLifecycle;

import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Sends the due email retries: every {@code helix.notification.email.retry.poll-interval} (5 s) each replica calls
 * {@link EmailOutbox#processDue()} on one background thread. Replicas share the queue; the store's claim makes sure
 * each retry is sent by one of them. Stops with the application; an email that was being retried then becomes due
 * again when its claim runs out.
 */
public class EmailRetryWorker implements SmartLifecycle {

    private static final Logger LOG = LogManager.getLogger(EmailRetryWorker.class);

    private final EmailOutbox outbox;
    private final Duration pollInterval;
    private final boolean enabled;
    private volatile ScheduledExecutorService executor;

    /** @param enabled false when retries are off: the worker never polls */
    public EmailRetryWorker(final EmailOutbox outbox, final Duration pollInterval, final boolean enabled) {
        this.outbox = outbox;
        this.enabled = enabled;
        this.pollInterval = pollInterval == null || pollInterval.isNegative() || pollInterval.isZero()
                ? Duration.ofSeconds(5) : pollInterval;
    }

    @Override
    public synchronized void start() {
        if (executor != null || !enabled) {
            return;
        }
        executor = Executors.newSingleThreadScheduledExecutor(r -> {
            final Thread t = new Thread(r, "email-retry");
            t.setDaemon(true);
            return t;
        });
        executor.scheduleWithFixedDelay(this::poll, pollInterval.toMillis(), pollInterval.toMillis(),
                TimeUnit.MILLISECONDS);
    }

    /** One poll: send what is due, draining full batches. Never throws. */
    void poll() {
        try {
            int batches = 0;
            while (outbox.processDue() > 0 && ++batches < 50 && executor != null) {
                // A full queue is worked off batch by batch; the next poll continues.
            }
        } catch (final RuntimeException e) {
            LOG.warn("Email retry poll failed: {}", LogSafe.sanitize(e.getClass().getSimpleName()));
        }
    }

    @Override
    public synchronized void stop() {
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }
    }

    @Override
    public boolean isRunning() {
        return executor != null;
    }
}
