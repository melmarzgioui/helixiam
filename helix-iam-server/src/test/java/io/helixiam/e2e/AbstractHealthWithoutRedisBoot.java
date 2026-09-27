/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.CompositeHealth;
import org.springframework.boot.actuate.health.HealthComponent;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * C4: a real boot with PostgreSQL sessions and NO Redis reachable (Redis points at a closed port), then
 * {@code GET /actuator/health}. The aggregate must be UP and there must be no Redis contributor — neither the
 * imperative nor the reactive one. Subclasses choose how the session store is selected (the Helm chart's
 * {@code HELIX_SESSION_STORE=queue}, or the dev profile's default). Each boots its own context on a random port and
 * deliberately does not share {@link AbstractE2eTest}'s Redis.
 */
abstract class AbstractHealthWithoutRedisBoot {

    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("helixiam").withUsername("helixiam").withPassword("helixiam");

    static {
        POSTGRES.start();
    }

    @DynamicPropertySource
    static void properties(final DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.readonly.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.data.redis.host", () -> "127.0.0.1");
        registry.add("spring.data.redis.port", AbstractHealthWithoutRedisBoot::closedPort);
        registry.add("spring.data.redis.timeout", () -> "500ms");
    }

    @LocalServerPort
    private int port;

    @Autowired
    private HealthEndpoint healthEndpoint;

    @Test
    void aggregateHealthIsUp_withoutAnyRedisContributor() throws Exception {
        final HealthComponent health = healthEndpoint.health();
        final Map<String, HealthComponent> components = health instanceof CompositeHealth c ? c.getComponents() : Map.of();
        assertThat(components).as("health components: %s", components).doesNotContainKey("redis");

        final HttpResponse<String> response = HttpClient.newHttpClient().send(HttpRequest.newBuilder(
                URI.create("http://localhost:" + port + "/actuator/health")).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        final JsonNode body = new ObjectMapper().readTree(response.body());
        assertThat(body.path("status").asText()).as(response.body()).isEqualTo("UP");
        assertThat(body.path("components").has("redis")).as(response.body()).isFalse();
    }

    private static int closedPort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort(); // closed again when this returns: nothing listens there
        } catch (final IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
