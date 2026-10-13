/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.application.ApplicationConfigPublisher;
import io.helixiam.authorization.amqp.client.ClientAdminPublisher;
import io.helixiam.authorization.amqp.federation.IdentityProviderConfigPublisher;
import io.helixiam.authorization.amqp.saml.SamlRelyingPartyConfigPublisher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Helix IAM (E8.6): a live health snapshot for the admin console's Health screen.
 *
 * <p>HelixIAM is a single Spring Boot process — there is no message broker and no separate
 * identity-domain service to probe. The {@code *Publisher} interfaces this controller calls
 * (e.g. {@link ApplicationConfigPublisher}) are in-process local adapters wired straight to the
 * JPA/JDBC services that back them; the "publisher" naming is a holdover from the pre-1.0 AMQP
 * architecture and carries no transport at runtime today (see {@code ADAPTERS.md}).
 *
 * <p>The snapshot reports three kinds of component: the server itself (always up, since it is
 * answering this request), a real {@code SELECT 1} probe of the PostgreSQL database, and —
 * only when Redis is actually configured as the session or token store — a Redis {@code PING}.
 * Realm object counts are best-effort reads through the existing admin services and never affect
 * overall status. Overall status is "healthy" only when every shown component is up.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/health")
public class HealthAdminController {

    private final ApplicationConfigPublisher applications;
    private final ClientAdminPublisher clients;
    private final SamlRelyingPartyConfigPublisher samlRelyingParties;
    private final IdentityProviderConfigPublisher identityProviders;
    private final JdbcTemplate jdbcTemplate;
    private final RedisConnectionFactory redisConnectionFactory;
    private final boolean redisConfigured;

    public HealthAdminController(final ApplicationConfigPublisher applications,
                                final ClientAdminPublisher clients,
                                final SamlRelyingPartyConfigPublisher samlRelyingParties,
                                final IdentityProviderConfigPublisher identityProviders,
                                final JdbcTemplate jdbcTemplate,
                                final RedisConnectionFactory redisConnectionFactory,
                                @Value("${helix.iam.session-store:}") final String sessionStore,
                                @Value("${helix.iam.token-store:}") final String tokenStore) {
        this.applications = applications;
        this.clients = clients;
        this.samlRelyingParties = samlRelyingParties;
        this.identityProviders = identityProviders;
        this.jdbcTemplate = jdbcTemplate;
        this.redisConnectionFactory = redisConnectionFactory;
        this.redisConfigured = "redis".equals(sessionStore) || "redis".equals(tokenStore);
    }

    /** One platform component's health. */
    public record Component(String name, String status, String detail) {
    }

    public record HealthSnapshot(String overall, List<Component> components, Map<String, Integer> counts,
                                 String checkedAt) {
    }

    @GetMapping
    public HealthSnapshot health(@PathVariable final String realmId) {
        final List<Component> components = new ArrayList<>();
        boolean allUp = true;

        // The server is up by definition — it is answering this request.
        components.add(new Component("Server (OAuth/OIDC)", "up", "Serving admin + token endpoints"));

        final String dbFailure = probeDatabase();
        final boolean dbUp = dbFailure == null;
        components.add(new Component("Database (PostgreSQL)", dbUp ? "up" : "down",
                dbUp ? "SELECT 1 succeeded" : "SELECT 1 failed: " + dbFailure));
        allUp &= dbUp;

        if (redisConfigured) {
            final String redisFailure = probeRedis();
            final boolean redisUp = redisFailure == null;
            components.add(new Component("Redis", redisUp ? "up" : "down",
                    redisUp ? "PING succeeded" : "PING failed: " + redisFailure));
            allUp &= redisUp;
        }

        // Realm object counts are best-effort reads through the in-process admin services; a single
        // failure shouldn't blank the whole page or affect overall status.
        final Map<String, Integer> counts = new LinkedHashMap<>();
        countQuietly(counts, "applications", () -> applications.list(realmId).size());
        countQuietly(counts, "oidcClients", () -> clients.list(realmId).size());
        countQuietly(counts, "samlRelyingParties", () -> samlRelyingParties.list(realmId).size());
        countQuietly(counts, "identityProviders", () -> identityProviders.list(realmId).size());

        final String overall = allUp ? "healthy" : "degraded";
        return new HealthSnapshot(overall, components, counts, Instant.now().toString());
    }

    /** @return {@code null} on success, or the failing exception's simple class name (never its message). */
    private String probeDatabase() {
        try {
            jdbcTemplate.queryForObject("SELECT 1", Integer.class);
            return null;
        } catch (final RuntimeException e) {
            return e.getClass().getSimpleName();
        }
    }

    /** @return {@code null} on success, or the failing exception's simple class name (never its message). */
    private String probeRedis() {
        try (RedisConnection connection = redisConnectionFactory.getConnection()) {
            connection.ping();
            return null;
        } catch (final RuntimeException e) {
            return e.getClass().getSimpleName();
        }
    }

    private static void countQuietly(final Map<String, Integer> counts, final String key,
                                     final java.util.function.IntSupplier supplier) {
        try {
            counts.put(key, supplier.getAsInt());
        } catch (final RuntimeException ignored) {
            // Leave the key absent; the console shows "—" for a count it can't read.
        }
    }
}
