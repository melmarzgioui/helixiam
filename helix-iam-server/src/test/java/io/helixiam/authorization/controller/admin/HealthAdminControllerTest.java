/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.application.ApplicationConfigPublisher;
import io.helixiam.authorization.amqp.client.ClientAdminPublisher;
import io.helixiam.authorization.amqp.federation.IdentityProviderConfigPublisher;
import io.helixiam.authorization.amqp.saml.SamlRelyingPartyConfigPublisher;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * HelixIAM runs as a single process: no broker, no separate identity-domain service. The Health screen must
 * reflect that — a real DB probe, Redis only when configured, and no leftover AMQP/"identity domain" component
 * names from the pre-1.0 architecture.
 */
class HealthAdminControllerTest {

    private ApplicationConfigPublisher applications() {
        final ApplicationConfigPublisher p = mock(ApplicationConfigPublisher.class);
        when(p.list(anyString())).thenReturn(Collections.emptyList());
        return p;
    }

    private ClientAdminPublisher clients() {
        final ClientAdminPublisher p = mock(ClientAdminPublisher.class);
        when(p.list(anyString())).thenReturn(Collections.emptyList());
        return p;
    }

    private SamlRelyingPartyConfigPublisher saml() {
        final SamlRelyingPartyConfigPublisher p = mock(SamlRelyingPartyConfigPublisher.class);
        when(p.list(anyString())).thenReturn(Collections.emptyList());
        return p;
    }

    private IdentityProviderConfigPublisher idps() {
        final IdentityProviderConfigPublisher p = mock(IdentityProviderConfigPublisher.class);
        when(p.list(anyString())).thenReturn(Collections.emptyList());
        return p;
    }

    @Test
    void healthySnapshotListsExactlyServerAndDatabase_whenRedisIsNotConfigured() {
        final JdbcTemplate jdbc = mock(JdbcTemplate.class);
        when(jdbc.queryForObject(eq("SELECT 1"), eq(Integer.class))).thenReturn(1);
        final RedisConnectionFactory redis = mock(RedisConnectionFactory.class);

        final HealthAdminController controller = new HealthAdminController(
                applications(), clients(), saml(), idps(), jdbc, redis, "queue", "queue");

        final HealthAdminController.HealthSnapshot snap = controller.health("master");

        assertThat(snap.overall()).isEqualTo("healthy");
        assertThat(snap.components()).extracting(HealthAdminController.Component::name)
                .containsExactly("Server (OAuth/OIDC)", "Database (PostgreSQL)");
        assertThat(snap.components()).allSatisfy(c -> assertThat(c.status()).isEqualTo("up"));
        assertThat(snap.components().stream().map(String::valueOf).reduce("", String::concat))
                .doesNotContainIgnoringCase("amqp")
                .doesNotContainIgnoringCase("rabbitmq")
                .doesNotContainIgnoringCase("message queue")
                .doesNotContain("identity domain");
    }

    @Test
    void redisComponentAppears_onlyWhenRedisIsConfigured() {
        final JdbcTemplate jdbc = mock(JdbcTemplate.class);
        when(jdbc.queryForObject(eq("SELECT 1"), eq(Integer.class))).thenReturn(1);
        final RedisConnectionFactory redis = mock(RedisConnectionFactory.class);
        final RedisConnection connection = mock(RedisConnection.class);
        when(redis.getConnection()).thenReturn(connection);
        when(connection.ping()).thenReturn("PONG");

        final HealthAdminController controller = new HealthAdminController(
                applications(), clients(), saml(), idps(), jdbc, redis, "redis", "queue");

        final HealthAdminController.HealthSnapshot snap = controller.health("master");

        assertThat(snap.overall()).isEqualTo("healthy");
        assertThat(snap.components()).extracting(HealthAdminController.Component::name)
                .containsExactly("Server (OAuth/OIDC)", "Database (PostgreSQL)", "Redis");
        assertThat(snap.components()).allSatisfy(c -> assertThat(c.status()).isEqualTo("up"));
    }

    @Test
    void aDatabaseFailure_showsDownAndDegraded_withNoExceptionMessageLeaked() {
        final JdbcTemplate jdbc = mock(JdbcTemplate.class);
        final String secret = "Connection to host=10.1.2.3 user=helixiam password=s3cr3t-value refused";
        when(jdbc.queryForObject(eq("SELECT 1"), eq(Integer.class)))
                .thenThrow(new DataAccessResourceFailureException(secret));
        final RedisConnectionFactory redis = mock(RedisConnectionFactory.class);

        final HealthAdminController controller = new HealthAdminController(
                applications(), clients(), saml(), idps(), jdbc, redis, "queue", "queue");

        final HealthAdminController.HealthSnapshot snap = controller.health("master");

        assertThat(snap.overall()).isEqualTo("degraded");
        final HealthAdminController.Component db = snap.components().stream()
                .filter(c -> c.name().equals("Database (PostgreSQL)")).findFirst().orElseThrow();
        assertThat(db.status()).isEqualTo("down");
        assertThat(db.detail()).doesNotContain("10.1.2.3", "s3cr3t-value", "password", secret)
                .contains("DataAccessResourceFailureException");
    }

    @Test
    void aRedisFailure_showsDownAndDegraded_withNoExceptionMessageLeaked() {
        final JdbcTemplate jdbc = mock(JdbcTemplate.class);
        when(jdbc.queryForObject(eq("SELECT 1"), eq(Integer.class))).thenReturn(1);
        final RedisConnectionFactory redis = mock(RedisConnectionFactory.class);
        final String secret = "Could not connect to redis://redispass:hunter2@10.9.9.9:6379";
        when(redis.getConnection()).thenThrow(new org.springframework.data.redis.RedisConnectionFailureException(secret));

        final HealthAdminController controller = new HealthAdminController(
                applications(), clients(), saml(), idps(), jdbc, redis, "redis", "queue");

        final HealthAdminController.HealthSnapshot snap = controller.health("master");

        assertThat(snap.overall()).isEqualTo("degraded");
        final HealthAdminController.Component redisComponent = snap.components().stream()
                .filter(c -> c.name().equals("Redis")).findFirst().orElseThrow();
        assertThat(redisComponent.status()).isEqualTo("down");
        assertThat(redisComponent.detail()).doesNotContain("hunter2", "10.9.9.9", secret)
                .contains("RedisConnectionFailureException");
    }

    @Test
    void realmCountsAreStillReported() {
        final JdbcTemplate jdbc = mock(JdbcTemplate.class);
        when(jdbc.queryForObject(eq("SELECT 1"), eq(Integer.class))).thenReturn(1);
        final RedisConnectionFactory redis = mock(RedisConnectionFactory.class);

        final HealthAdminController controller = new HealthAdminController(
                applications(), clients(), saml(), idps(), jdbc, redis, "queue", "queue");

        final HealthAdminController.HealthSnapshot snap = controller.health("master");

        assertThat(snap.counts()).containsKeys("applications", "oidcClients", "samlRelyingParties",
                "identityProviders");
    }
}
