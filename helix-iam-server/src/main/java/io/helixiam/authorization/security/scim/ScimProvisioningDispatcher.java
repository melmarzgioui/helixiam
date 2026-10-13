/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.scim;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.helixiam.authorization.amqp.scim.ScimTargetConfigPublisher;
import io.helixiam.authorization.amqp.scim.ScimTargetDto;
import io.helixiam.authorization.security.webhook.WebhookDispatcher;
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

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
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
    /** 5 s per request in total (DNS, connect, TLS, response); a response body is read up to 1 MB. */
    private static final PinnedHttpFetcher.Limits LIMITS = new PinnedHttpFetcher.Limits(Duration.ofSeconds(5),
            Duration.ofSeconds(5), 1024 * 1024);

    private final ObjectProvider<ScimTargetConfigPublisher> publisher;
    private final ObjectMapper mapper;
    private final OutboundUrlGuard egressGuard;
    /** M6: pinned to the address the guard validated (no second DNS answer), no redirects, 5 s in total. */
    private final PinnedHttpFetcher http;
    private final RealmBoundedExecutor queue;
    private final LongSupplier nowMillis;
    private final ConcurrentHashMap<String, Cached> cache = new ConcurrentHashMap<>();

    @Autowired
    public ScimProvisioningDispatcher(final ObjectProvider<ScimTargetConfigPublisher> publisher,
                                      final ObjectMapper mapper, final OutboundUrlGuard egressGuard) {
        this(publisher, mapper, egressGuard, System::currentTimeMillis);
    }

    ScimProvisioningDispatcher(final ObjectProvider<ScimTargetConfigPublisher> publisher, final ObjectMapper mapper,
                               final OutboundUrlGuard egressGuard, final LongSupplier nowMillis) {
        this.publisher = publisher;
        this.mapper = mapper;
        this.egressGuard = egressGuard;
        this.nowMillis = nowMillis;
        this.http = PinnedHttpFetcher.plain(egressGuard, FetchLimiter.Group.OUTBOUND, () -> null);
        // a virtual thread per delivery, at most 1,000 pending per realm (overflow dropped, never blocking the
        // producer); a slow endpoint holds its own thread, bounded in time by the request deadline and in number by
        // the realm's share of the OUTBOUND slots and of this queue
        this.queue = new RealmBoundedExecutor("scim-provisioner", RealmBoundedExecutor.DEFAULT_MAX_PENDING_PER_REALM);
    }

    /** The ceiling on pending deliveries across all realms ({@code helix.outbound.deliveries.max-pending}). */
    @Autowired(required = false)
    void setMaxPendingTotal(
            @org.springframework.beans.factory.annotation.Value("${helix.outbound.deliveries.max-pending:20000}")
            final int maxPendingTotal) {
        queue.setMaxPendingTotal(maxPendingTotal);
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
                queue.submit(realm, () -> push(target, operation, user));
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
            // M6: the guard resolves the realm's SCIM URL once, inside the deadline; the GET goes to that address
            final Map<String, String> headers = new LinkedHashMap<>();
            headers.put("Accept", "application/scim+json");
            authed(target, headers);
            final PinnedHttpFetcher.Response res = http.exchange(new PinnedHttpFetcher.Request("GET",
                    ScimProvisioningClient.externalIdFilterUrl(target.baseUrl(), userId), headers, null, LIMITS,
                    false).inPartition(target.realmId()));
            if (res.status() >= 300) {
                return null;
            }
            final JsonNode root = mapper.readTree(res.bodyAsString());
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
        // M6: one resolution inside the deadline, the request goes to the validated address, no redirects
        final Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/scim+json");
        headers.put("Accept", "application/scim+json");
        authed(target, headers);
        final PinnedHttpFetcher.Response res = http.exchange(new PinnedHttpFetcher.Request(method, url, headers,
                body == null ? null : body.getBytes(StandardCharsets.UTF_8), LIMITS, false)
                .inPartition(target.realmId())); // the realm's own share of the OUTBOUND slots
        if (res.status() >= 300) {
            LOG.debug("SCIM {} {} returned {}", method, url, res.status());
        }
    }

    private static void authed(final ScimTargetDto target, final Map<String, String> headers) {
        if (target.token() != null && !target.token().isBlank()) {
            headers.put("Authorization", "Bearer " + target.token());
        }
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
            LOG.debug("SCIM target lookup failed for realm {}: {}",
                    LogSafe.sanitize(realm), LogSafe.sanitize(e.getMessage()));
            return List.of();
        }
    }

    /** The per-realm bounded delivery queue (pending and dropped counts per realm). */
    public RealmBoundedExecutor queue() {
        return queue;
    }

    private record Cached(List<ScimTargetDto> value, long loadedAt) {
    }
}
