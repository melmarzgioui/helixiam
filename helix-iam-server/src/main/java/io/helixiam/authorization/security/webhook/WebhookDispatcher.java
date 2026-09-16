package io.helixiam.authorization.security.webhook;

import io.helixiam.authorization.amqp.webhook.WebhookConfigPublisher;
import io.helixiam.authorization.amqp.webhook.WebhookSubscriptionDto;
import io.helixiam.authorization.security.audit.AuditEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
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

    private final ObjectProvider<WebhookConfigPublisher> publisher;
    private final HttpClient httpClient;
    private final ExecutorService executor;
    private final LongSupplier nowMillis;
    private final ConcurrentHashMap<String, Cached> cache = new ConcurrentHashMap<>();

    @Autowired
    public WebhookDispatcher(final ObjectProvider<WebhookConfigPublisher> publisher) {
        this(publisher, System::currentTimeMillis);
    }

    WebhookDispatcher(final ObjectProvider<WebhookConfigPublisher> publisher, final LongSupplier nowMillis) {
        this.publisher = publisher;
        this.nowMillis = nowMillis;
        this.httpClient = HttpClient.newHttpClient();
        this.executor = Executors.newFixedThreadPool(2, r -> {
            final Thread t = new Thread(r, "webhook-dispatcher");
            t.setDaemon(true);
            return t;
        });
    }

    /** Deliver one event (already serialized to {@code json}) to every matching, enabled webhook. */
    public void dispatch(final AuditEvent event, final String json) {
        if (event == null || event.realm() == null || event.realm().isBlank() || json == null) {
            return;
        }
        final List<WebhookSubscriptionDto> hooks = activeFor(event.realm());
        for (final WebhookSubscriptionDto hook : hooks) {
            if (matches(hook.eventTypes(), event.type(), event.category())) {
                executor.submit(() -> post(hook, json));
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
            LOG.debug("Webhook lookup failed for realm {}: {}", realm, e.getMessage());
            return List.of();
        }
    }

    private void post(final WebhookSubscriptionDto hook, final String json) {
        try {
            final HttpRequest.Builder req = HttpRequest.newBuilder()
                    .uri(URI.create(hook.url()))
                    .timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "application/json")
                    .header("X-Helix-Event", "audit")
                    .POST(HttpRequest.BodyPublishers.ofString(json));
            final String sig = sign(hook.secret(), json);
            if (!sig.isEmpty()) {
                req.header("X-Helix-Signature", "sha256=" + sig);
            }
            final HttpResponse<Void> res = httpClient.send(req.build(), HttpResponse.BodyHandlers.discarding());
            if (res.statusCode() >= 300) {
                LOG.debug("Webhook {} returned {}", hook.id(), res.statusCode());
            }
        } catch (final Exception e) {
            LOG.debug("Webhook {} delivery failed (non-fatal): {}", hook.id(), e.getMessage());
        }
    }

    private record Cached(List<WebhookSubscriptionDto> value, long loadedAt) {
    }
}
