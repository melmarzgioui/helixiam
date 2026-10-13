/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.service.PasswordEncoderService;
import io.helixiam.authorization.service.realm.RealmAdminBootstrapService;
import io.helixiam.testsupport.LogCapture;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * L6, over a whole boot: with no {@code HELIX_ADMIN_PASSWORD}, the generated bootstrap admin password is written to
 * {@code HELIX_ADMIN_PASSWORD_FILE} with owner-only (0600) permissions, it is the admin's password, and no log line of
 * the boot (every logger, captured from before the context starts) carries it — only the file's path. Its own
 * PostgreSQL (the shared e2e context sets an admin password).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "HELIX_SESSION_STORE=queue",
        "database.encryption=0123456789abcdef0123456789abcdef",
        "idp.base.url=http://localhost:8080",
        "sp.base.url=http://localhost:8090"})
@DirtiesContext
class AdminPasswordFileBootE2eTest {

    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("helixiam").withUsername("helixiam").withPassword("helixiam");
    static final Path PASSWORD_FILE;
    /**
     * Every log line of the boot, captured from before the context starts, two ways: the live Log4j configuration
     * (when an earlier context in this JVM already configured logging, Spring keeps it) and the console the Spring
     * configuration writes to (when this boot configures logging itself, which replaces the live configuration).
     */
    static final LogCapture ALL_LOGS = LogCapture.all();
    static final LogCapture BOOTSTRAP_LOGS = LogCapture.of(RealmAdminBootstrapService.class);
    static final java.io.PrintStream ORIGINAL_OUT = System.out;
    static final java.io.ByteArrayOutputStream CONSOLE = new java.io.ByteArrayOutputStream();

    static {
        // The tee holds its own references, never this class's statics: another thread (a poller of an earlier test's
        // context) can write to System.out while this class is still initialising, and reading a static here would
        // wait for that initialisation while holding the log appender's lock, which the initialising thread (logging
        // the container start below) then waits for: a deadlock that hung the build.
        final java.io.PrintStream original = ORIGINAL_OUT;
        final java.io.ByteArrayOutputStream console = CONSOLE;
        System.setOut(new java.io.PrintStream(new java.io.OutputStream() {
            @Override
            public void write(final int b) {
                original.write(b);
                synchronized (console) {
                    console.write(b);
                }
            }

            @Override
            public void write(final byte[] b, final int off, final int len) {
                original.write(b, off, len);
                synchronized (console) {
                    console.write(b, off, len);
                }
            }
        }, true, java.nio.charset.StandardCharsets.UTF_8));
        POSTGRES.start();
        try {
            PASSWORD_FILE = Files.createTempDirectory("helix-admin-").resolve("admin-password");
        } catch (final IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @DynamicPropertySource
    static void properties(final DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.readonly.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.data.redis.host", () -> "127.0.0.1");
        registry.add("spring.data.redis.port", () -> "1");
        registry.add("spring.data.redis.timeout", () -> "500ms");
        registry.add("helix.admin.password", () -> "");
        registry.add("helix.admin.password-file", PASSWORD_FILE::toString);
    }

    @AfterAll
    static void closeCaptures() {
        System.setOut(ORIGINAL_OUT);
        ALL_LOGS.close();
        BOOTSTRAP_LOGS.close();
    }

    @Autowired
    private UserCredentialsRepository users;

    @Autowired
    private PasswordEncoderService passwords;

    @Test
    void theGeneratedPassword_isIn0600File_isTheAdminsPassword_andNeverLogged() throws Exception {
        assertThat(PASSWORD_FILE).exists();
        assertThat(Files.getPosixFilePermissions(PASSWORD_FILE)).isEqualTo(PosixFilePermissions.fromString("rw-------"));
        final String password = Files.readString(PASSWORD_FILE).strip();
        assertThat(password).hasSizeGreaterThanOrEqualTo(24);

        final UserCredentials admin = users.findByRealmIdAndUsername("master", "admin").orElseThrow();
        assertThat(passwords.matches(password, admin.getPassword(), admin.getPasswordSaltValue())).isTrue();

        final String logs;
        synchronized (CONSOLE) {
            logs = BOOTSTRAP_LOGS.text() + "\n" + ALL_LOGS.text() + "\n"
                    + CONSOLE.toString(java.nio.charset.StandardCharsets.UTF_8);
        }
        assertThat(logs).as("the boot's log names the file").contains(PASSWORD_FILE.toString());
        assertThat(logs).as("but never the password").doesNotContain(password);
    }
}
