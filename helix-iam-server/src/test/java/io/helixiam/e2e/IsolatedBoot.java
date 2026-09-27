/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ServerSocket;

/**
 * A booted server on a random port with its own PostgreSQL and NO Redis reachable (Redis points at a closed port) —
 * for tests that need their own boot properties and so cannot share {@link AbstractE2eTest}'s context. Subclasses
 * put their properties on {@code @SpringBootTest(properties = ...)} (visible to environment post-processors).
 */
abstract class IsolatedBoot {

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
        registry.add("spring.data.redis.port", IsolatedBoot::closedPort);
        registry.add("spring.data.redis.timeout", () -> "500ms");
    }

    @LocalServerPort
    protected int port;

    /** {@code http://localhost:{port}}. */
    protected String baseUrl() {
        return "http://localhost:" + port;
    }

    private static int closedPort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort(); // closed again when this returns: nothing listens there
        } catch (final IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
