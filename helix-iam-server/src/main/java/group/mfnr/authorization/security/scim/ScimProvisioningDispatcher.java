package group.mfnr.authorization.security.scim;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import group.mfnr.authorization.amqp.scim.ScimTargetConfigPublisher;
import group.mfnr.authorization.amqp.scim.ScimTargetDto;
import group.mfnr.authorization.security.webhook.WebhookDispatcher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.LongSupplier;

/**
 * Helix IAM B7: pushes local user lifecycle changes out to each realm's enabled outbound SCIM 2.0 targets
 * (the auth server as a SCIM <i>client</i>). Per-realm targets are cached (30s TTL) and loaded over AMQP
 * via {@link ScimTargetConfigPublisher}; delivery is best-effort on a daemon pool so a slow/unreachable
 * service provider never blocks the admin request. The Helix {@code userId} is carried as the SCIM
 * {@code externalId}; updates/deletes first resolve the remote resource id via an {@code externalId}
 * filter, so no local id-mapping is stored. Each request carries {@code Authorization: Bearer <token>}.
 */
@Component
public class ScimProvisioningDispatcher {

    /** The user lifecycle operations that can be provisioned outward. */
    public enum Operation { CREATE, UPDATE, DELETE }

    private static final Logger LOG = LogManager.getLogger(ScimProvisioningDispatcher.class);
    private static final long TTL_MS = 30_000L;

    private final ObjectProvider<ScimTargetConfigPublisher> publisher;
    private final ObjectMapper mapper;
    private final HttpClient httpClient;
    private final ExecutorService executor;
    private final LongSupplier nowMillis;
    private final ConcurrentHashMap<String, Cached> cache = new ConcurrentHashMap<>();

    @Autowired
    public ScimProvisioningDispatcher(final ObjectProvider<ScimTargetConfigPublisher> publisher,
                                      final ObjectMapper mapper) {
        this(publisher, mapper, System::currentTimeMillis);
    }

    ScimProvisioningDispatcher(final ObjectProvider<ScimTargetConfigPublisher> publisher, final ObjectMapper mapper,
                               final LongSupplier nowMillis) {
        this.publisher = publisher;
        this.mapper = mapper;
        this.nowMillis = nowMillis;
        this.httpClient = HttpClient.newHttpClient();
        this.executor = Executors.newFixedThreadPool(2, r -> {
            final Thread t = new Thread(r, "scim-provisioner");
            t.setDaemon(true);
            return t;
        });
    }

    /** Fan a user lifecycle change out to every matching, enabled SCIM target for the realm (best-effort). */
    public void provision(final String realm, final Operation operation, final ScimUserView user) {
        if (realm == null || realm.isBlank() || operation == null || user == null || user.userId() == null) {
            return;
        }
        final String eventType = "USER_" + operation.name();
        for (final ScimTargetDto target : activeFor(realm)) {
            if (target.baseUrl() != null && !target.baseUrl().isBlank()
                    && WebhookDispatcher.matches(target.eventTypes(), eventType, "USER")) {
                executor.submit(() -> push(target, operation, user));
            }
        }
    }

    private void push(final ScimTargetDto target, final Operation operation, final ScimUserView user) {
        try {
            switch (operation) {
                case CREATE -> create(target, user);
                case UPDATE -> {
                    final String remoteId = findRemoteId(target, user.userId());
                    if (remoteId == null) {
                        create(target, user); // not yet provisioned downstream → create it
                    } else {
                        send(target, "PUT", ScimProvisioningClient.usersUrl(target.baseUrl()) + "/" + remoteId,
                                body(user));
                    }
                }
                case DELETE -> {
                    final String remoteId = findRemoteId(target, user.userId());
                    if (remoteId != null) {
                        send(target, "DELETE", ScimProvisioningClient.usersUrl(target.baseUrl()) + "/" + remoteId, null);
                    }
                }
                default -> { }
            }
        } catch (final Exception e) {
            LOG.debug("SCIM provisioning to target {} ({}) failed (non-fatal): {}",
                    target.id(), operation, e.getMessage());
        }
    }

    private void create(final ScimTargetDto target, final ScimUserView user) throws Exception {
        send(target, "POST", ScimProvisioningClient.usersUrl(target.baseUrl()), body(user));
    }

    /** Resolve the downstream resource id for our externalId; null if absent or the lookup fails. */
    private String findRemoteId(final ScimTargetDto target, final String userId) {
        try {
            final HttpRequest req = authed(target, HttpRequest.newBuilder()
                    .uri(URI.create(ScimProvisioningClient.externalIdFilterUrl(target.baseUrl(), userId)))
                    .timeout(Duration.ofSeconds(5))
                    .header("Accept", "application/scim+json")
                    .GET()).build();
            final HttpResponse<String> res = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() >= 300) {
                return null;
            }
            final JsonNode root = mapper.readTree(res.body());
            final JsonNode resources = root.get("Resources");
            if (resources != null && resources.isArray() && !resources.isEmpty()) {
                final JsonNode id = resources.get(0).get("id");
                return id == null ? null : id.asText();
            }
            return null;
        } catch (final Exception e) {
            LOG.debug("SCIM externalId lookup failed for target {}: {}", target.id(), e.getMessage());
            return null;
        }
    }

    private String body(final ScimUserView user) throws Exception {
        return mapper.writeValueAsString(ScimProvisioningClient.userResource(user));
    }

    private void send(final ScimTargetDto target, final String method, final String url, final String body)
            throws Exception {
        final HttpRequest.Builder req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(5))
                .header("Content-Type", "application/scim+json")
                .header("Accept", "application/scim+json");
        final HttpRequest.BodyPublisher pub = body == null
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body);
        req.method(method, pub);
        final HttpResponse<Void> res = httpClient.send(authed(target, req).build(), HttpResponse.BodyHandlers.discarding());
        if (res.statusCode() >= 300) {
            LOG.debug("SCIM {} {} returned {}", method, url, res.statusCode());
        }
    }

    private static HttpRequest.Builder authed(final ScimTargetDto target, final HttpRequest.Builder req) {
        if (target.token() != null && !target.token().isBlank()) {
            req.header("Authorization", "Bearer " + target.token());
        }
        return req;
    }

    private List<ScimTargetDto> activeFor(final String realm) {
        final Cached cached = cache.get(realm);
        if (cached != null && nowMillis.getAsLong() - cached.loadedAt < TTL_MS) {
            return cached.value;
        }
        try {
            final ScimTargetConfigPublisher p = publisher.getIfAvailable();
            final List<ScimTargetDto> fresh = p == null ? List.of() : p.active(realm);
            cache.put(realm, new Cached(fresh == null ? List.of() : fresh, nowMillis.getAsLong()));
            return cache.get(realm).value;
        } catch (final RuntimeException e) {
            LOG.debug("SCIM target lookup failed for realm {}: {}", realm, e.getMessage());
            return List.of();
        }
    }

    private record Cached(List<ScimTargetDto> value, long loadedAt) {
    }
}
