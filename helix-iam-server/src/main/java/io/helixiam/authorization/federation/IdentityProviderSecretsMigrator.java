/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.helixiam.common.log.LogSafe;
import io.helixiam.persistence.security.AttributeEncryption;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Task 4 (security): moves identity-provider secrets ({@link ProviderSecretKeys}) out of the plaintext
 * {@code identity_provider.config_json} into {@code secret_json}, encrypted with {@link AttributeEncryption} exactly as
 * the JPA column converter writes it. Shared by Flyway {@code V75.1} and, on the {@code schema.sql} path, the startup
 * {@link IdentityProviderSecretsBackfill}. Idempotent: a row whose {@code config_json} holds no secret key is not
 * touched, so a second run changes nothing. A secret already in {@code secret_json} wins over a legacy copy.
 */
public class IdentityProviderSecretsMigrator {

    private static final Logger LOG = LogManager.getLogger(IdentityProviderSecretsMigrator.class);
    private static final TypeReference<LinkedHashMap<String, String>> MAP = new TypeReference<>() {
    };

    private final AttributeEncryption encryption;
    private final ObjectMapper json = new ObjectMapper();

    public IdentityProviderSecretsMigrator(final AttributeEncryption encryption) {
        this.encryption = encryption;
    }

    /** Moves the secrets of every row that still has some in {@code config_json}; returns the number of rows moved. */
    public int migrate(final Connection connection) throws SQLException {
        final List<Row> rows = new ArrayList<>();
        try (PreparedStatement select = connection.prepareStatement(
                "SELECT id, protocol, config_json, secret_json FROM identity_provider");
             ResultSet rs = select.executeQuery()) {
            while (rs.next()) {
                rows.add(new Row(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)));
            }
        }
        int moved = 0;
        try (PreparedStatement update = connection.prepareStatement(
                "UPDATE identity_provider SET config_json = ?, secret_json = ? WHERE id = ?")) {
            for (final Row row : rows) {
                final Map<String, String> config = read(row.configJson());
                if (config == null || config.keySet().stream().noneMatch(k -> ProviderSecretKeys.isSecret(row.protocol(), k))) {
                    continue;
                }
                final Map<String, String> stored = storedSecrets(row);
                if (stored == null) {
                    LOG.warn("Identity provider {}: stored secrets are unreadable (wrong DB_ENCRYPTION?); its legacy "
                            + "secrets stay in config_json", LogSafe.sanitize(row.id()));
                    continue;
                }
                final ProviderSecretKeys.Split split = ProviderSecretKeys.split(row.protocol(), config);
                final Map<String, String> secrets = new LinkedHashMap<>(split.secrets());
                secrets.putAll(stored);
                update.setString(1, write(split.plain()));
                update.setString(2, secrets.isEmpty() ? null : encryption.convertToDatabaseColumn(write(secrets)));
                update.setString(3, row.id());
                update.executeUpdate();
                moved++;
            }
        }
        if (moved > 0) {
            LOG.info("Moved the secrets of {} identity provider(s) out of config_json into encrypted secret_json", moved);
        }
        return moved;
    }

    /**
     * The row's current {@code secret_json} secrets; {@code null} when they cannot be read. The converter fails closed
     * on a value it cannot decrypt (it throws): that is one row's problem, so it is caught here and the row skipped
     * (logged by id only, never the value), instead of aborting the backfill of every other row.
     */
    private Map<String, String> storedSecrets(final Row row) {
        if (row.secretJson() == null || row.secretJson().isBlank()) {
            return Map.of();
        }
        try {
            return read(encryption.convertToEntityAttribute(row.secretJson()));
        } catch (final RuntimeException e) {
            return null;
        }
    }

    private Map<String, String> read(final String value) {
        if (value == null || value.isBlank()) {
            return Map.of();
        }
        try {
            return json.readValue(value, MAP);
        } catch (final Exception e) {
            return null;
        }
    }

    private String write(final Map<String, String> map) {
        try {
            return json.writeValueAsString(map);
        } catch (final Exception e) {
            throw new IllegalStateException("Could not serialise identity-provider config", e);
        }
    }

    private record Row(String id, String protocol, String configJson, String secretJson) {
    }
}
