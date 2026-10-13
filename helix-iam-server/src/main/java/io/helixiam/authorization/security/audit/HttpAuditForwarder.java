/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.audit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Helix IAM E8.5-S4 (Events): pushes an audit JSON line to the configured SIEM webhook
 * ({@code helix.audit.http.url}). Fire-and-forget on a small bounded executor with a short timeout, so a
 * slow or unreachable SIEM never blocks the request thread or breaks the action being audited. All
 * errors are swallowed (logged at debug) — audit delivery is best-effort; the durable copy is stdout.
 *
 * <p>Bounded: the connect timeout and the request timeout are explicit ({@code helix.audit.http.timeout-ms},
 * default 2 s, at most 30 s; a zero or negative value means the default), redirects are not followed, and at most
 * {@link #MAX_PENDING} lines wait; more are dropped (counted, logged at warn once a minute).
 */
@Component
public class HttpAuditForwarder {

    private static final Logger LOG = LogManager.getLogger(HttpAuditForwarder.class);

    static final int MAX_PENDING = 1_000;
    static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(2);
    static final Duration MAX_TIMEOUT = Duration.ofSeconds(30);

    private final HelixAuditProperties props;
    private final HttpClient httpClient;
    private final ThreadPoolExecutor executor;
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong lastDropLog = new AtomicLong();

    public HttpAuditForwarder(final HelixAuditProperties props) {
        this.props = props;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(requestTimeout())
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        // Daemon threads, bounded pool and backlog — audit forwarding must never keep the JVM alive or starve it.
        this.executor = new ThreadPoolExecutor(2, 2, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(MAX_PENDING), r -> {
                    final Thread t = new Thread(r, "audit-forwarder");
                    t.setDaemon(true);
                    return t;
                }, new ThreadPoolExecutor.AbortPolicy());
    }

    /** The per-request timeout: the configured one within (0, 30 s], else 2 s. */
    Duration requestTimeout() {
        final int ms = props.getHttp().getTimeoutMs();
        if (ms <= 0) {
            return DEFAULT_TIMEOUT;
        }
        final Duration configured = Duration.ofMillis(ms);
        return configured.compareTo(MAX_TIMEOUT) > 0 ? MAX_TIMEOUT : configured;
    }

    /** Lines waiting to be sent. */
    int pending() {
        return executor.getQueue().size();
    }

    /** Lines dropped because the backlog was full. */
    long dropped() {
        return dropped.get();
    }

    /** Best-effort async POST of a pre-serialized audit line; no-op when no webhook is configured. */
    public void forward(final String json) {
        if (!props.httpConfigured()) {
            return;
        }
        try {
            executor.execute(() -> post(json));
        } catch (final RejectedExecutionException e) {
            final long total = dropped.incrementAndGet();
            final long now = System.currentTimeMillis();
            final long last = lastDropLog.get();
            if (now - last >= 60_000 && lastDropLog.compareAndSet(last, now)) {
                LOG.warn("Audit webhook backlog full ({} lines); {} audit lines dropped so far (stdout keeps them)",
                        MAX_PENDING, total);
            }
        }
    }

    /** One POST; true on a 2xx. */
    boolean post(final String json) {
        try {
            final HelixAuditProperties.Http http = props.getHttp();
            final HttpRequest.Builder req = HttpRequest.newBuilder()
                    .uri(URI.create(http.getUrl()))
                    .timeout(requestTimeout())
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json));
            if (http.authConfigured()) {
                req.header("Authorization", http.getAuthHeader());
            }
            final HttpResponse<Void> res = httpClient.send(req.build(), HttpResponse.BodyHandlers.discarding());
            if (res.statusCode() >= 300) {
                LOG.debug("SIEM webhook returned {} for audit POST", res.statusCode());
                return false;
            }
            return true;
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } catch (final Exception e) {
            LOG.debug("Audit webhook delivery failed (non-fatal): {}", e.getMessage());
            return false;
        }
    }
}
