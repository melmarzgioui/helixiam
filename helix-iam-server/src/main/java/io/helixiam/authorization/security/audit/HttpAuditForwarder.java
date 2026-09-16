package io.helixiam.authorization.security.audit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Helix IAM E8.5-S4 (Events): pushes an audit JSON line to the configured SIEM webhook
 * ({@code helix.audit.http.url}). Fire-and-forget on a small bounded executor with a short timeout, so a
 * slow or unreachable SIEM never blocks the request thread or breaks the action being audited. All
 * errors are swallowed (logged at debug) — audit delivery is best-effort; the durable copy is stdout.
 */
@Component
public class HttpAuditForwarder {

    private static final Logger LOG = LogManager.getLogger(HttpAuditForwarder.class);

    private final HelixAuditProperties props;
    private final HttpClient httpClient;
    private final ExecutorService executor;

    public HttpAuditForwarder(final HelixAuditProperties props) {
        this.props = props;
        this.httpClient = HttpClient.newHttpClient();
        // Daemon threads, bounded pool — audit forwarding must never keep the JVM alive or starve it.
        this.executor = Executors.newFixedThreadPool(2, r -> {
            final Thread t = new Thread(r, "audit-forwarder");
            t.setDaemon(true);
            return t;
        });
    }

    /** Best-effort async POST of a pre-serialized audit line; no-op when no webhook is configured. */
    public void forward(final String json) {
        if (!props.httpConfigured()) {
            return;
        }
        executor.submit(() -> post(json));
    }

    private void post(final String json) {
        try {
            final HelixAuditProperties.Http http = props.getHttp();
            final HttpRequest.Builder req = HttpRequest.newBuilder()
                    .uri(URI.create(http.getUrl()))
                    .timeout(Duration.ofMillis(http.getTimeoutMs()))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json));
            if (http.authConfigured()) {
                req.header("Authorization", http.getAuthHeader());
            }
            final HttpResponse<Void> res = httpClient.send(req.build(), HttpResponse.BodyHandlers.discarding());
            if (res.statusCode() >= 300) {
                LOG.debug("SIEM webhook returned {} for audit POST", res.statusCode());
            }
        } catch (final Exception e) {
            LOG.debug("Audit webhook delivery failed (non-fatal): {}", e.getMessage());
        }
    }
}
