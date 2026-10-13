/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.webhook;

import io.helixiam.authorization.amqp.webhook.WebhookConfigPublisher;
import io.helixiam.authorization.amqp.webhook.WebhookSubscriptionDto;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.common.net.FetchLimiter;
import io.helixiam.common.net.RealmBoundedExecutor;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.net.PinnedHttpFetcher;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Helix IAM B6: fans each emitted {@link AuditEvent} out to the realm's enabled webhook subscriptions
 * (event-listener SPI). Per-realm active subscriptions are cached (30s TTL) and loaded over AMQP via
 * {@link WebhookConfigPublisher}; delivery is best-effort on a daemon pool with a short timeout, so a
 * slow/unreachable endpoint never blocks the request thread. Each POST carries an
 * {@code X-Helix-Signature: sha256=<hmac>} header so receivers can verify authenticity with the secret.
 */
@Component
public class WebhookDispatcher {

    private static final Logger LOG = LogManager.getLogger(WebhookDispatcher.class);
    private static final long TTL_MS = 30_000L;
    /** 5 s for the whole delivery (DNS, connect, TLS, response); a 200 body is read up to 64 KB and ignored. */
    private static final PinnedHttpFetcher.Limits LIMITS = new PinnedHttpFetcher.Limits(Duration.ofSeconds(5),
            Duration.ofSeconds(5), 64 * 1024);

    private final ObjectProvider<WebhookConfigPublisher> publisher;
    private final OutboundUrlGuard egressGuard;
    /** M6: pinned to the address the guard validated (no second DNS answer), no redirects, 5 s in total. */
    private final PinnedHttpFetcher http;
    private final RealmBoundedExecutor queue;
    private final LongSupplier nowMillis;
    private final ConcurrentHashMap<String, Cached> cache = new ConcurrentHashMap<>();

    @Autowired
    public WebhookDispatcher(final ObjectProvider<WebhookConfigPublisher> publisher, final OutboundUrlGuard egressGuard) {
        this(publisher, egressGuard, System::currentTimeMillis);
    }

    WebhookDispatcher(final ObjectProvider<WebhookConfigPublisher> publisher, final OutboundUrlGuard egressGuard,
                      final LongSupplier nowMillis) {
        this.publisher = publisher;
        this.egressGuard = egressGuard;
        this.nowMillis = nowMillis;
        this.http = PinnedHttpFetcher.plain(egressGuard, FetchLimiter.Group.OUTBOUND, () -> null);
        // a virtual thread per delivery, at most 1,000 pending per realm (overflow dropped, never blocking the
        // producer); a slow endpoint holds its own thread, bounded in time by the request deadline and in number by
        // the realm's share of the OUTBOUND slots and of this queue
        this.queue = new RealmBoundedExecutor("webhook-dispatcher", RealmBoundedExecutor.DEFAULT_MAX_PENDING_PER_REALM);
    }

    /** The ceiling on pending deliveries across all realms ({@code helix.outbound.deliveries.max-pending}). */
    @Autowired(required = false)
    void setMaxPendingTotal(
            @org.springframework.beans.factory.annotation.Value("${helix.outbound.deliveries.max-pending:20000}")
            final int maxPendingTotal) {
        queue.setMaxPendingTotal(maxPendingTotal);
    }

    /** Deliver one event (already serialized to {@code json}) to every matching, enabled webhook. */
    public void dispatch(final AuditEvent event, final String json) {
        if (event == null || event.realm() == null || event.realm().isBlank() || json == null) {
            return;
        }
        final List<WebhookSubscriptionDto> hooks = activeFor(event.realm());
        for (final WebhookSubscriptionDto hook : hooks) {
            if (matches(hook.eventTypes(), event.type(), event.category())) {
                queue.submit(event.realm(), () -> post(hook, json, event.realm()));
            }
        }
    }

    /** True when the (comma-joined) filter is blank/empty, or contains the event's type or category. */
    public static boolean matches(final String eventTypesCsv, final String type, final String category) {
        if (eventTypesCsv == null || eventTypesCsv.isBlank()) {
            return true; // no filter → all events
        }
        final Set<String> wanted = new HashSet<>();
        Arrays.stream(eventTypesCsv.split(",")).map(String::trim).filter(s -> !s.isEmpty())
                .forEach(s -> wanted.add(s.toUpperCase()));
        return (type != null && wanted.contains(type.toUpperCase()))
                || (category != null && wanted.contains(category.toUpperCase()));
    }

    /** HMAC-SHA256 of the body under the secret, lowercase hex (empty string when no secret). */
    public static String sign(final String secret, final String body) {
        if (secret == null || secret.isBlank()) {
            return "";
        }
        try {
            final Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            final byte[] sig = mac.doFinal(body.getBytes(StandardCharsets.UTF_8));
            final StringBuilder hex = new StringBuilder(sig.length * 2);
            for (final byte b : sig) {
                hex.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
            }
            return hex.toString();
        } catch (final Exception e) {
            return "";
        }
    }

    private List<WebhookSubscriptionDto> activeFor(final String realm) {
        final Cached cached = cache.get(realm);
        if (cached != null && nowMillis.getAsLong() - cached.loadedAt < TTL_MS) {
            return cached.value;
        }
        try {
            final WebhookConfigPublisher p = publisher.getIfAvailable();
            final List<WebhookSubscriptionDto> fresh = p == null ? List.of() : p.active(realm);
            cache.put(realm, new Cached(fresh == null ? List.of() : fresh, nowMillis.getAsLong()));
            return cache.get(realm).value;
        } catch (final RuntimeException e) {
            LOG.debug("Webhook lookup failed for realm {}: {}",
                    LogSafe.sanitize(realm), LogSafe.sanitize(e.getMessage()));
            return List.of();
        }
    }

    private void post(final WebhookSubscriptionDto hook, final String json, final String realm) {
        try {
            // M6: the guard resolves the realm's webhook URL once, inside the deadline, and the POST goes to the
            // address it validated (internal / metadata hosts refused), without following redirects
            final Map<String, String> headers = new LinkedHashMap<>();
            headers.put("Content-Type", "application/json");
            headers.put("X-Helix-Event", "audit");
            final String sig = sign(hook.secret(), json);
            if (!sig.isEmpty()) {
                headers.put("X-Helix-Signature", "sha256=" + sig);
            }
            // the realm's own share of the OUTBOUND slots: a slow endpoint cannot hold other realms' deliveries
            final PinnedHttpFetcher.Response res = http.exchange(new PinnedHttpFetcher.Request("POST", hook.url(),
                    headers, json.getBytes(StandardCharsets.UTF_8), LIMITS, false).inPartition(realm));
            if (res.status() >= 300) {
                LOG.debug("Webhook {} returned {}", hook.id(), res.status());
            }
        } catch (final Exception e) {
            LOG.debug("Webhook {} delivery failed (non-fatal): {}", hook.id(), e.getMessage());
        }
    }

    /** The per-realm bounded delivery queue (pending and dropped counts per realm). */
    public RealmBoundedExecutor queue() {
        return queue;
    }

    private record Cached(List<WebhookSubscriptionDto> value, long loadedAt) {
    }
}
