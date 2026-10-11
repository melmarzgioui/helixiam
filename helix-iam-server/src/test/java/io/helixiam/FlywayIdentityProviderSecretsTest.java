/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam;

import io.helixiam.authorization.federation.V75_1__Move_identity_provider_secrets;
import io.helixiam.persistence.security.AttributeEncryption;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Task 4 (security): V75 adds {@code identity_provider.secret_json}; V75.1 moves every secret key (per protocol,
 * {@code ProviderSecretKeys}) out of the plaintext {@code config_json} into it, encrypted with {@code DB_ENCRYPTION}.
 * Rows without secrets are left alone.
 */
@Testcontainers
class FlywayIdentityProviderSecretsTest {

    @Container
    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    private static final String KEY = "0123456789abcdef0123456789abcdef";

    @Test
    void secretsMoveOutOfConfigJson_encrypted() {
        final DriverManagerDataSource ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).locations("classpath:db/migration").target("74").load().migrate();
        final JdbcTemplate jdbc = new JdbcTemplate(ds);
        jdbc.update("INSERT INTO identity_provider (id, realm_id, alias, protocol, display_name, config_json) VALUES "
                + "('r|up','r','up','oidc','Up','{\"clientId\":\"web\",\"clientSecret\":\"oidc-s3cret\"}'), "
                + "('r|digid','r','digid','digid','DigiD',"
                + "  '{\"ssoUrl\":\"https://idp\",\"spSigningPrivateKey\":\"PEM-sign\",\"spDecryptionPrivateKey\":\"PEM-dec\"}'), "
                + "('r|plain','r','plain','saml','Plain','{\"ssoUrl\":\"https://saml\"}')");

        final AttributeEncryption encryption = new AttributeEncryption(KEY);
        Flyway.configure().dataSource(ds).locations("classpath:db/migration")
                .javaMigrations(new V75_1__Move_identity_provider_secrets(encryption))
                .load().migrate();

        assertThat(jdbc.queryForObject("SELECT config_json FROM identity_provider WHERE id = 'r|up'", String.class))
                .isEqualTo("{\"clientId\":\"web\"}");
        final String upSecret = jdbc.queryForObject("SELECT secret_json FROM identity_provider WHERE id = 'r|up'",
                String.class);
        assertThat(upSecret).doesNotContain("oidc-s3cret");
        assertThat(encryption.convertToEntityAttribute(upSecret)).isEqualTo("{\"clientSecret\":\"oidc-s3cret\"}");

        assertThat(jdbc.queryForObject("SELECT config_json FROM identity_provider WHERE id = 'r|digid'", String.class))
                .isEqualTo("{\"ssoUrl\":\"https://idp\"}");
        assertThat(encryption.convertToEntityAttribute(jdbc.queryForObject(
                "SELECT secret_json FROM identity_provider WHERE id = 'r|digid'", String.class)))
                .contains("\"spSigningPrivateKey\":\"PEM-sign\"").contains("\"spDecryptionPrivateKey\":\"PEM-dec\"");

        assertThat(jdbc.queryForObject("SELECT secret_json FROM identity_provider WHERE id = 'r|plain'", String.class))
                .as("no secrets, nothing written").isNull();
        assertThat(jdbc.queryForObject("SELECT config_json FROM identity_provider WHERE id = 'r|plain'", String.class))
                .isEqualTo("{\"ssoUrl\":\"https://saml\"}");
    }
}
