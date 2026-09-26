/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ServerSocket;

/**
 * Base class for end-to-end tests that drive the REAL HTTP endpoints of a fully booted HelixIAM server
 * (embedded Tomcat on a real port, full security chains, real login form, real Spring Authorization Server).
 *
 * <h2>Infrastructure</h2>
 * <ul>
 *   <li><b>One Postgres for the whole JVM</b> — a singleton Testcontainers {@code postgres:16-alpine}
 *       started in a static initializer (NOT {@code @Container} per class), so every subclass shares one
 *       database and — because they share the identical configuration declared here — one cached Spring
 *       context / one running server. Subclasses must therefore NOT add their own
 *       {@code @DynamicPropertySource}/{@code @TestPropertySource}/{@code @MockBean} (that forks a second
 *       context on the same fixed port → bind failure), and must seed data with unique names
 *       ({@link E2eSeed#unique}). Ryuk removes the container when the JVM exits.</li>
 *   <li><b>Fixed free port chosen up front</b> ({@code DEFINED_PORT} + {@code server.port}) rather than
 *       {@code RANDOM_PORT}, so {@code idp.base.url} (SAML entity/broker callback/session URLs) can point at the
 *       real server before the context starts. The OIDC {@code issuer} does NOT depend on it: SAS derives it
 *       from the request ({@code http://localhost:{port}/realms/{realm}}), as no issuer is configured.</li>
 *   <li><b>One Redis for the whole JVM</b> ({@code redis:7-alpine}, same singleton pattern). It is REQUIRED
 *       for any real HTTP login: Spring Session Data Redis is on the classpath and the project default is
 *       {@code helix.iam.session-store=redis}. {@code spring.session.store-type=none} (copied from the context
 *       tests) is a no-op on Boot 3 — that property was removed — so without a live Redis the context still
 *       boots (MockMvc tests never create a session) but the first request that saves a session 500s with
 *       {@code RedisConnectionFailureException}. The OAuth2 authorization store stays the in-process
 *       Postgres adapter.</li>
 * </ul>
 *
 * <h2>Settings that keep the login password-only (no MFA / required actions / flow engine)</h2>
 * <ul>
 *   <li>{@code mfa.enabled=false} — the default is {@code true}, which sends EVERY successful password login
 *       to {@code /mfa/enable} (TOTP enrolment) or {@code /mfa/totp}. With it off, the success handler stamps
 *       {@code auth_time} and resumes the saved {@code /oauth2/authorize} request.</li>
 *   <li>{@code helix.flow-engine.enabled=false} (the default) — otherwise the data-driven flow ({@code /flow})
 *       runs after the password step.</li>
 *   <li>Seeded users have no required actions and realms keep {@code requireMfa=false},
 *       {@code breachedPasswordCheck=false}, CAPTCHA off (all {@code RealmConfig} defaults).</li>
 *   <li>{@code helix.security.cookie-secure=false} — the session + {@code XSRF-TOKEN} cookies are
 *       {@code Secure} by default and would never be sent back over plain http by the test client.</li>
 * </ul>
 * A future TOTP-enforcement test that needs {@code mfa.enabled=true} cannot share this context; it should
 * either use the flow engine / realm {@code requireMfa} path, or subclass with its own port+properties.
 *
 * <h2>Admin</h2>
 * The master realm's bootstrap admin is {@value #ADMIN_USERNAME} / {@value #ADMIN_PASSWORD}
 * ({@code helix.admin.password}); {@link #adminSession()} logs it in for session+CSRF calls to {@code /admin/**}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
public abstract class AbstractE2eTest {

    public static final String MASTER = "master";
    public static final String ADMIN_USERNAME = "admin";
    public static final String ADMIN_PASSWORD = "E2e-Admin-Passw0rd!";

    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("helixiam")
                    .withUsername("helixiam")
                    .withPassword("helixiam");

    /** HTTP-session store (Spring Session Data Redis) — see class javadoc. */
    @SuppressWarnings("resource")
    static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);

    /** The server's port, chosen once per JVM before the (single, cached) context starts. */
    static final int PORT;

    static {
        POSTGRES.start();
        REDIS.start();
        PORT = freePort();
    }

    @DynamicPropertySource
    static void e2eProperties(final DynamicPropertyRegistry registry) {
        // --- same as LoginSecurityHeadersTest / ContextLoadsTest ---
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.readonly.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("database.encryption", () -> "0123456789abcdef0123456789abcdef");
        registry.add("idp.base.url", () -> baseUrlFor(PORT));
        registry.add("sp.base.url", () -> "http://localhost:8090");
        // Schema path: Flyway (the default) or the legacy schema.sql bootstrap — -Dhelix.e2e.schema=sql-init
        // runs the whole e2e suite on the other path from an empty database.
        final boolean sqlInit = "sql-init".equals(System.getProperty("helix.e2e.schema", "flyway"));
        registry.add("spring.sql.init.mode", () -> sqlInit ? "always" : "never");
        registry.add("spring.flyway.enabled", () -> sqlInit ? "false" : "true");
        registry.add("spring.session.store-type", () -> "none");

        // --- e2e: a real port + the password-only login path (see class javadoc) ---
        registry.add("server.port", () -> PORT);
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        registry.add("mfa.enabled", () -> "false");
        registry.add("helix.flow-engine.enabled", () -> "false");
        registry.add("helix.security.cookie-secure", () -> "false");
        // Every e2e request comes from 127.0.0.1; lift the per-IP login/token buckets so the suite never 429s.
        registry.add("helix.ratelimit.login.burst", () -> "100000");
        registry.add("helix.ratelimit.token.burst", () -> "100000");
        registry.add("helix.e2e.forced-errors", () -> "true"); // ForcedErrorTestController
        registry.add("helix.admin.username", () -> ADMIN_USERNAME);
        registry.add("helix.admin.password", () -> ADMIN_PASSWORD);
    }

    @Autowired
    protected ApplicationContext context;

    private E2eSeed seed;

    /** {@code http://localhost:{port}} — no trailing slash. */
    protected static String baseUrl() {
        return baseUrlFor(PORT);
    }

    /** Seeding helpers bound to the running context. */
    protected E2eSeed seed() {
        if (seed == null) {
            seed = new E2eSeed(context);
        }
        return seed;
    }

    /** A fresh user agent (empty cookie jar). */
    protected E2eHttp newBrowser() {
        return new E2eHttp(baseUrl());
    }

    /** An OIDC driver for {@code realm} using a fresh browser. */
    protected OidcFlow oidc(final String realm) {
        return new OidcFlow(newBrowser(), realm);
    }

    /** The master realm's bootstrap admin, logged in (session + CSRF) for {@code /admin/**} calls. */
    protected E2eAdminSession adminSession() {
        return E2eAdminSession.login(newBrowser(), MASTER, ADMIN_USERNAME, ADMIN_PASSWORD);
    }

    /** The bootstrapped admin of {@code realm} ({@code admin-<realm>}; same configured password). */
    protected E2eAdminSession adminSession(final String realm) {
        return MASTER.equals(realm) ? adminSession()
                : E2eAdminSession.login(newBrowser(), realm, ADMIN_USERNAME + "-" + realm, ADMIN_PASSWORD);
    }

    private static String baseUrlFor(final int port) {
        return "http://localhost:" + port;
    }

    private static int freePort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            socket.setReuseAddress(true);
            return socket.getLocalPort();
        } catch (final IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
