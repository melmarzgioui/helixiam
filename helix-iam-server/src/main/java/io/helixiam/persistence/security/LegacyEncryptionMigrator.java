/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.persistence.security;

import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * L5: rewrites every value of every {@link AttributeEncryption} column that is still in the legacy AES/ECB format in
 * the current AES-GCM format ({@link AttributeEncryption#reencryptLegacy}). Modelled on the identity-provider secrets
 * migrator: plain JDBC, one row at a time, idempotent (a rewritten row is current and is not touched again), logged by
 * table, column and row id only, never a value. A row that neither format reads (a changed key, an altered value, a
 * plaintext row awaiting the plaintext migration) is skipped and reported, never aborts the others.
 *
 * <p>Only values whose base64 decodes to whole AES blocks can be in the legacy format, so the scan asks the database
 * for those rows alone; a value that is not valid base64 is not legacy and is left to the converter's read path.
 */
public class LegacyEncryptionMigrator {

    private static final Logger LOG = LogManager.getLogger(LegacyEncryptionMigrator.class);

    /** One encrypted column: its table, the SQL expression naming a row, and the column. */
    public record EncryptedColumn(String table, String idExpression, String column) {
        String name() {
            return table + "." + column;
        }
    }

    /**
     * Every column written through {@link AttributeEncryption}: the JPA {@code @Convert} columns and the JDBC stores
     * (signing keys, wallet pepper). Not listed: {@code email_retry.payload}, a JSON document whose fields are
     * encrypted individually and that only the AES-GCM era has ever written.
     */
    public static final List<EncryptedColumn> COLUMNS = List.of(
            new EncryptedColumn("realm_key", "key_id", "private_key"),
            new EncryptedColumn("user_credentials", "user_id", "mfa_secret"),
            new EncryptedColumn("mfa_hotp", "user_id", "secret"),
            new EncryptedColumn("service_provider_oauth", "service_provider_id", "client_secret"),
            new EncryptedColumn("scim_target", "id", "token"),
            new EncryptedColumn("webhook_subscription", "id", "secret"),
            new EncryptedColumn("identity_provider", "id", "secret_json"),
            new EncryptedColumn("messaging_provider", "id", "secret"),
            new EncryptedColumn("saml_relying_party", "id", "signing_certificate"),
            new EncryptedColumn("saml_relying_party", "id", "encryption_certificate"),
            new EncryptedColumn("verifier_signing_key", "realm_id || '/' || name", "private_key"),
            new EncryptedColumn("realm_wallet_pepper", "realm_id", "pepper"));

    /**
     * What a run did: rows rewritten, the rows ({@code table.column id}) it could not read, and the columns
     * ({@code table.column}) whose migration failed as a whole (a database error).
     */
    public record Result(int reEncrypted, List<String> unreadable, List<String> failedColumns) {
        public Result(final int reEncrypted, final List<String> unreadable) {
            this(reEncrypted, unreadable, List.of());
        }
    }

    private final AttributeEncryption encryption;
    private final List<EncryptedColumn> columns;

    public LegacyEncryptionMigrator(final AttributeEncryption encryption) {
        this(encryption, COLUMNS);
    }

    LegacyEncryptionMigrator(final AttributeEncryption encryption, final List<EncryptedColumn> columns) {
        this.encryption = encryption;
        this.columns = List.copyOf(columns);
    }

    /** Every column, on one connection (one transaction when the caller has one). */
    public Result migrate(final Connection connection) throws SQLException {
        int reEncrypted = 0;
        final List<String> unreadable = new ArrayList<>();
        for (final EncryptedColumn column : columns) {
            final Result one = migrateColumn(connection, column);
            reEncrypted += one.reEncrypted();
            unreadable.addAll(one.unreadable());
        }
        if (reEncrypted > 0) {
            LOG.info("Re-encrypted {} value(s) from the legacy AES/ECB format to AES-GCM", reEncrypted);
        }
        return new Result(reEncrypted, List.copyOf(unreadable));
    }

    /** One column: its legacy rows rewritten, in id order (replicas booting together lock rows in the same order). */
    public Result migrateColumn(final Connection connection, final EncryptedColumn column) throws SQLException {
        int reEncrypted = 0;
        final List<String> unreadable = new ArrayList<>();
        for (final String[] row : candidates(connection, column)) {
            final String id = row[0];
            final String stored = row[1];
            final String current;
            try {
                current = encryption.reencryptLegacy(stored);
            } catch (final RuntimeException e) {
                unreadable.add(column.name() + " " + id);
                LOG.warn("{} of row {}: neither the current nor the legacy format reads it with this DB_ENCRYPTION "
                        + "key; skipped", column.name(), LogSafe.sanitize(id));
                continue;
            }
            if (current == null) {
                continue; // already the current format
            }
            if (update(connection, column, id, stored, current)) {
                reEncrypted++;
                LOG.info("{} of row {}: re-encrypted from the legacy AES/ECB format to AES-GCM", column.name(),
                        LogSafe.sanitize(id));
            }
        }
        return new Result(reEncrypted, List.copyOf(unreadable));
    }

    /** The columns this migrator covers. */
    public List<EncryptedColumn> columns() {
        return columns;
    }

    /** The rows whose value base64-decodes to whole AES blocks (the only ones that can be legacy). */
    private static List<String[]> candidates(final Connection connection, final EncryptedColumn column)
            throws SQLException {
        final String value = column.column();
        // decoded length = 3/4 of the base64 length minus its '=' padding; a multiple of 16 can be AES/ECB
        final String sql = "SELECT " + column.idExpression() + ", " + value + " FROM " + column.table()
                + " WHERE " + value + " IS NOT NULL AND " + value + " ~ '^[A-Za-z0-9+/]+=?=?$'"
                + " AND length(" + value + ") % 4 = 0"
                + " AND (length(" + value + ") / 4 * 3 - (length(" + value + ") - length(rtrim(" + value + ", '=')))) % 16 = 0"
                + " ORDER BY " + column.idExpression();
        final List<String[]> rows = new ArrayList<>();
        try (PreparedStatement select = connection.prepareStatement(sql);
             ResultSet rs = select.executeQuery()) {
            while (rs.next()) {
                rows.add(new String[] {rs.getString(1), rs.getString(2)});
            }
        }
        return rows;
    }

    /** Rewrites one row, only if it still holds the value read (a concurrent write wins). */
    private static boolean update(final Connection connection, final EncryptedColumn column, final String id,
                                  final String stored, final String current) throws SQLException {
        final String sql = "UPDATE " + column.table() + " SET " + column.column() + " = ? WHERE "
                + column.idExpression() + " = ? AND " + column.column() + " = ?";
        try (PreparedStatement update = connection.prepareStatement(sql)) {
            update.setString(1, current);
            update.setString(2, id);
            update.setString(3, stored);
            return update.executeUpdate() > 0;
        }
    }
}
