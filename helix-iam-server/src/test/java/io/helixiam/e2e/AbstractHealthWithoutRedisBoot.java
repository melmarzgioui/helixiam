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
abstract class AbstractHealthWithoutRedisBoot extends IsolatedBoot {

    @Autowired
    private HealthEndpoint healthEndpoint;

    @Test
    void aggregateHealthIsUp_withoutAnyRedisContributor() throws Exception {
        final HealthComponent health = healthEndpoint.health();
        final Map<String, HealthComponent> components = health instanceof CompositeHealth c ? c.getComponents() : Map.of();
        assertThat(components).as("health components: %s", components).doesNotContainKey("redis");

        final HttpResponse<String> response = HttpClient.newHttpClient().send(HttpRequest.newBuilder(
                URI.create(baseUrl() + "/actuator/health")).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        final JsonNode body = new ObjectMapper().readTree(response.body());
        assertThat(body.path("status").asText()).as(response.body()).isEqualTo("UP");
        assertThat(body.path("components").has("redis")).as(response.body()).isFalse();
    }
}
