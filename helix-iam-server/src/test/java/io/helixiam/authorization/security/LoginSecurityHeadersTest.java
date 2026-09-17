/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

/**
 * Security review M3: the server-rendered login chain must ship a Content-Security-Policy plus the
 * clickjacking / MIME-sniffing hardening headers. This boots the full merged context (Testcontainers
 * Postgres, like {@link io.helixiam.ContextLoadsTest}) so the real {@code @Order(2)} SecurityFilterChain
 * is exercised, then GETs the seeded master realm's {@code /login} and asserts the headers.
 *
 * <p>The page lives under {@code /realms/{realm}/login} — a bare {@code /login} is 404'd by
 * {@code RealmRoutingFilter} before Spring Security runs, so the header writers never fire. The master realm
 * is seeded on startup by {@code RealmBootstrap} (an {@code ApplicationRunner}).
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class LoginSecurityHeadersTest {

    @Container
    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("kubeiam")
                    .withUsername("kubeiam")
                    .withPassword("kubeiam");

    @DynamicPropertySource
    static void datasourceProperties(final DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.readonly.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("database.encryption", () -> "0123456789abcdef0123456789abcdef");
        registry.add("spring.sql.init.mode", () -> "always");
        registry.add("spring.flyway.enabled", () -> "false");
        registry.add("spring.session.store-type", () -> "none");
    }

    @Autowired
    private MockMvc mvc;

    @Test
    void loginPageShipsContentSecurityPolicyAndClickjackingHeaders() throws Exception {
        mvc.perform(get("/realms/master/login"))
                // A real, working CSP: self-only scripts (NO 'unsafe-inline' for script-src), framing denied.
                .andExpect(header().string("Content-Security-Policy", allOf(
                        containsString("default-src 'self'"),
                        containsString("base-uri 'self'"),
                        containsString("frame-ancestors 'none'"),
                        containsString("object-src 'none'"),
                        containsString("form-action 'self'"),
                        containsString("script-src 'self'"),
                        not(containsString("script-src 'unsafe-inline'")),
                        not(containsString("script-src 'self' 'unsafe-inline'")))))
                // Clickjacking + MIME-sniffing + referrer hardening.
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Referrer-Policy", "strict-origin-when-cross-origin"));
    }
}
