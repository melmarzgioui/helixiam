/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import io.helixiam.authorization.security.FilteredJdkRedisSerializer;
import io.helixiam.testsupport.LogCapture;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.session.data.redis.RedisIndexedSessionRepository;
import org.testcontainers.containers.GenericContainer;

import javax.management.BadAttributeValueExpException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code spring.session.data.redis.repository-type=indexed}: Spring Session's {@link RedisIndexedSessionRepository} only
 * returns no session when the mapper refuses one, it does not delete it. HelixIAM's mapper deletes the refused
 * session's keys itself, so the session is gone (signed out) and the WARN is logged once, not on every request. Real
 * Redis, the production serializer and customizer.
 */
class RedisIndexedSessionDropTest {

    @SuppressWarnings("resource")
    private static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);
    private static LettuceConnectionFactory connections;
    private static RedisIndexedSessionRepository repository;

    @BeforeAll
    static void start() {
        REDIS.start();
        connections = new LettuceConnectionFactory(new RedisStandaloneConfiguration(REDIS.getHost(),
                REDIS.getMappedPort(6379)));
        connections.afterPropertiesSet();
        connections.start();
        final RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connections);
        template.setKeySerializer(RedisSerializer.string());
        template.setHashKeySerializer(RedisSerializer.string());
        template.setDefaultSerializer(new RedisSessionSerializationConfig().springSessionDefaultRedisSerializer());
        template.afterPropertiesSet();
        repository = new RedisIndexedSessionRepository(template);
        repository.setRedisKeyNamespace("helix-test");
        new RedisSessionSerializationConfig().dropUnreadableIndexedSessions("helix-test").customize(repository);
    }

    @AfterAll
    static void stop() {
        connections.destroy();
        REDIS.stop();
    }

    @Test
    void aRefusedSession_isDeleted_andLoggedOnce() {
        final String id = saved("planted-ok");
        plant(id, "sessionAttr:planted", new BadAttributeValueExpException("gadget"));
        assertThat(keyExists("helix-test:sessions:" + id)).isTrue();

        try (LogCapture log = LogCapture.of(RedisSessionSerializationConfig.class)) {
            assertThat(repository.findById(id)).isNull();
            assertThat(repository.findById(id)).isNull();
            assertThat(log.text().split("HTTP session dropped", -1)).as("logged once").hasSize(2);
        }
        assertThat(keyExists("helix-test:sessions:" + id)).as("session hash deleted").isFalse();
        assertThat(keyExists("helix-test:sessions:expires:" + id)).as("expiry key deleted").isFalse();
    }

    @Test
    void aReadableSession_isKept() {
        final String id = saved("ok");
        assertThat(repository.findById(id)).isNotNull();
        assertThat((Object) repository.findById(id).getAttribute("planted")).isEqualTo("ok");
        assertThat(keyExists("helix-test:sessions:" + id)).isTrue();
    }

    private static String saved(final String value) {
        final RedisIndexedSessionRepository.RedisSession session = repository.createSession();
        session.setAttribute("planted", value);
        repository.save(session);
        return session.getId();
    }

    private static void plant(final String id, final String field, final Object value) {
        try (var connection = connections.getConnection()) {
            connection.hashCommands().hSet(("helix-test:sessions:" + id).getBytes(StandardCharsets.UTF_8),
                    field.getBytes(StandardCharsets.UTF_8), new JdkSerializationRedisSerializer().serialize(value));
        }
    }

    private static boolean keyExists(final String key) {
        try (var connection = connections.getConnection()) {
            return Boolean.TRUE.equals(connection.keyCommands().exists(key.getBytes(StandardCharsets.UTF_8)));
        }
    }
}
