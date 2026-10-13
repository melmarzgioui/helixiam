/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.ApplicationContext;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * {@link TokenExchangeActorScenario} on the Redis token store ({@code HELIX_TOKEN_STORE=redis}). Its own boot (a token
 * store is chosen at start-up), with its own PostgreSQL and Redis.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "HELIX_SESSION_STORE=queue",
        "HELIX_TOKEN_STORE=redis",
        "database.encryption=0123456789abcdef0123456789abcdef",
        "idp.base.url=http://localhost:8080",
        "sp.base.url=http://localhost:8090",
        "spring.sql.init.mode=always",
        "spring.flyway.enabled=false",
        "mfa.enabled=false",
        "helix.flow-engine.enabled=false",
        "helix.security.cookie-secure=false"})
@DirtiesContext
class TokenExchangeActorRefusedRedisE2eTest {

    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("helixiam").withUsername("helixiam").withPassword("helixiam");
    @SuppressWarnings("resource")
    static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);

    static {
        POSTGRES.start();
        REDIS.start();
    }

    @DynamicPropertySource
    static void properties(final DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.readonly.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
    }

    @LocalServerPort
    private int port;

    @Autowired
    private ApplicationContext context;

    @Test
    void anActorToken_isInvalidRequest_andNothingIsStored() {
        scenario().anActorToken_isInvalidRequest_andNothingIsStored();
    }

    @Test
    void anExchangeWithoutAnActor_stillWorks() {
        scenario().anExchangeWithoutAnActor_stillWorks();
    }

    private TokenExchangeActorScenario scenario() {
        final StringRedisTemplate redis = new StringRedisTemplate(context.getBean(RedisConnectionFactory.class));
        return new TokenExchangeActorScenario(new E2eSeed(context),
                realm -> new OidcFlow(new E2eHttp("http://localhost:" + port), realm), () -> {
                    final var keys = redis.keys("helix:authz:id:*");
                    return keys == null ? 0 : keys.size();
                });
    }
}
