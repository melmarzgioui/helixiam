/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import io.helixiam.authorization.service.client.BootstrapServiceAccountService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * C5: provisioning without switching MFA off. With {@code HELIX_BOOTSTRAP_CLIENT_ID} and a secret file set, the first
 * boot creates a master-realm service account holding the master {@code admin} role; with MFA ON globally
 * ({@code mfa.enabled=true}, the production default) it gets a {@code client_credentials} token and provisions a new
 * realm through the admin API. A second run changes nothing.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "HELIX_SESSION_STORE=queue",
        "mfa.enabled=true",
        "helix.bootstrap.client-id=provisioner",
        "database.encryption=0123456789abcdef0123456789abcdef",
        "idp.base.url=http://localhost:8080",
        "sp.base.url=http://localhost:8090",
        "spring.sql.init.mode=always",
        "spring.flyway.enabled=false"})
class BootstrapServiceAccountE2eTest extends IsolatedBoot {

    private static final String SECRET = "provisioner-secret-from-a-mounted-file-0123456789";

    @DynamicPropertySource
    static void secretFile(final DynamicPropertyRegistry registry) {
        registry.add("helix.bootstrap.client-secret-file", () -> {
            try {
                final Path file = Files.createTempFile("helix-bootstrap-", ".secret");
                Files.writeString(file, SECRET + "\n");
                file.toFile().deleteOnExit();
                return file.toString();
            } catch (final IOException e) {
                throw new UncheckedIOException(e);
            }
        });
    }

    @Autowired
    private BootstrapServiceAccountService bootstrap;

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    void theBootstrapServiceAccount_provisionsARealm_withMfaOnGlobally() {
        final E2eHttp http = new E2eHttp(baseUrl());
        final String token = new OidcFlow(http, "master").clientCredentials("provisioner", SECRET, "openid").accessToken();

        final String realm = E2eSeed.unique("provisioned");
        final E2eHttp.Response created = http.sendJson("PUT", "/admin/realms/" + realm + "/settings",
                Map.of("displayName", "Provisioned", "accessTokenTtlSeconds", 300, "refreshTokenTtlSeconds", 86400,
                        "enabled", true, "passwordMinLength", 12),
                "Authorization", "Bearer " + token, "Accept", "application/json");
        assertThat(created.status()).as(created.toString()).isEqualTo(200);
        final E2eHttp.Response clients = http.get("/admin/realms/" + realm + "/clients",
                "Authorization", "Bearer " + token, "Accept", "application/json");
        assertThat(clients.status()).as(clients.toString()).isEqualTo(200);

        // The secret is stored like any client secret — never in plain text.
        final String stored = jdbc.queryForObject("SELECT client_secret FROM service_provider_oauth WHERE client_id = ? "
                + "AND realm_id = 'master' AND deleted = false", String.class, "provisioner");
        assertThat(stored).isNotBlank().doesNotContain(SECRET);
    }

    @Test
    void aSecondRun_changesNothing() {
        assertThat(bootstrap.ensureBootstrapServiceAccount()).isEqualTo(BootstrapServiceAccountService.Result.EXISTS);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM service_provider_oauth WHERE client_id = ? AND realm_id = "
                + "'master' AND deleted = false", Integer.class, "provisioner")).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM client_service_account_role WHERE client_id = ? AND "
                + "realm_id = 'master' AND role_name = 'admin'", Integer.class, "provisioner")).isEqualTo(1);
    }
}
