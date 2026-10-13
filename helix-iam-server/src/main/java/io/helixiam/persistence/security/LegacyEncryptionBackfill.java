/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.persistence.security;

import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import io.helixiam.common.startup.ProductionReadinessCheck;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * L5: at every startup (Flyway and {@code schema.sql} paths alike), re-encrypts any value still in the legacy AES/ECB
 * format ({@link LegacyEncryptionMigrator}), then turns the converter's ECB fallback off unless
 * {@code HELIX_DB_ENCRYPTION_ALLOW_LEGACY=true}. Idempotent: after the first run only current-format rows remain, so a
 * later start rewrites nothing. Rows it cannot read are named (table, column, id) in a production-readiness WARN. Each
 * column runs in its own transaction; a column that fails (a database error) is logged at ERROR (table and column only),
 * reported to {@link ProductionReadinessCheck#warnAfterStartup} and counted in the gauge
 * {@code helix_db_encryption_legacy_failed_columns}, and the fallback then stays on so legacy values still read; the next
 * start retries.
 */
@Component
public class LegacyEncryptionBackfill implements ApplicationRunner {

    private static final Logger LOG = LogManager.getLogger(LegacyEncryptionBackfill.class);
    /** The most row ids one readiness WARN names. */
    private static final int MAX_NAMED_ROWS = 50;

    private final DataSource dataSource;
    private final TransactionTemplate tx;
    private final AttributeEncryption encryption;
    private final boolean allowLegacy;
    private final ObjectProvider<ProductionReadinessCheck> readiness;
    /** Columns whose re-encryption failed at the last run (the gauge {@value #FAILED_COLUMNS_METRIC}). */
    private final AtomicInteger failedColumns = new AtomicInteger();
    static final String FAILED_COLUMNS_METRIC = "helix_db_encryption_legacy_failed_columns";

    public LegacyEncryptionBackfill(final DataSource dataSource, final PlatformTransactionManager transactionManager,
                                    @Value("${database.encryption:#{null}}") final String encryptionKey,
                                    @Value("${helix.security.db-encryption.allow-legacy:false}") final boolean allowLegacy,
                                    final ObjectProvider<ProductionReadinessCheck> readiness,
                                    final ObjectProvider<MeterRegistry> meters) {
        this.dataSource = dataSource;
        this.tx = new TransactionTemplate(transactionManager);
        this.encryption = new AttributeEncryption(encryptionKey);
        this.allowLegacy = allowLegacy;
        this.readiness = readiness;
        meters.ifAvailable(registry -> Gauge.builder(FAILED_COLUMNS_METRIC, failedColumns, AtomicInteger::get)
                .description("Encrypted columns whose legacy AES/ECB re-encryption failed at the last run")
                .register(registry));
    }

    @Override
    public void run(final ApplicationArguments args) {
        try {
            runOnce();
        } catch (final RuntimeException e) {
            LOG.warn("The legacy AES/ECB re-encryption failed; the legacy format stays readable and is retried on the "
                    + "next start: {}", LogSafe.sanitize(e.getMessage()));
        }
    }

    /** One run over every encrypted column: re-encrypt, report, then set the fallback. */
    public LegacyEncryptionMigrator.Result runOnce() {
        return runOnce(LegacyEncryptionMigrator.COLUMNS);
    }

    /**
     * One run over {@code columns}, each column in its own transaction so a failing one (a database error) neither
     * rolls back nor blocks the others. A failed column is logged at ERROR (table and column only), reported to the
     * production-readiness check and counted in {@code helix_db_encryption_legacy_failed_columns}; the ECB fallback then
     * stays on, so legacy TOTP secrets and keys in that column still read until the next start retries it.
     */
    public LegacyEncryptionMigrator.Result runOnce(final List<LegacyEncryptionMigrator.EncryptedColumn> columns) {
        final LegacyEncryptionMigrator migrator = new LegacyEncryptionMigrator(encryption, columns);
        int reEncrypted = 0;
        final List<String> unreadable = new ArrayList<>();
        final List<String> failedColumns = new ArrayList<>();
        for (final LegacyEncryptionMigrator.EncryptedColumn column : columns) {
            try {
                final LegacyEncryptionMigrator.Result one = tx.execute(status -> {
                    final Connection c = DataSourceUtils.getConnection(dataSource);
                    try {
                        return migrator.migrateColumn(c, column);
                    } catch (final SQLException e) {
                        throw new ColumnFailure(e);
                    } finally {
                        DataSourceUtils.releaseConnection(c, dataSource);
                    }
                });
                if (one != null) {
                    reEncrypted += one.reEncrypted();
                    unreadable.addAll(one.unreadable());
                }
            } catch (final RuntimeException e) {
                failedColumns.add(column.name());
                final Throwable cause = e instanceof ColumnFailure && e.getCause() != null ? e.getCause() : e;
                LOG.error("The legacy AES/ECB re-encryption of {} failed ({}{}); its legacy values stay readable and "
                                + "the next start retries it", column.name(), cause.getClass().getSimpleName(),
                        cause instanceof SQLException sql && sql.getSQLState() != null
                                ? ", SQLState " + LogSafe.sanitize(sql.getSQLState()) : "");
            }
        }
        if (reEncrypted > 0) {
            LOG.info("Re-encrypted {} value(s) from the legacy AES/ECB format to AES-GCM", reEncrypted);
        }
        final LegacyEncryptionMigrator.Result result =
                new LegacyEncryptionMigrator.Result(reEncrypted, List.copyOf(unreadable), List.copyOf(failedColumns));
        report(result);
        return result;
    }

    private void report(final LegacyEncryptionMigrator.Result result) {
        if (!result.unreadable().isEmpty()) {
            final List<String> named = result.unreadable().stream().limit(MAX_NAMED_ROWS)
                    .map(LogSafe::sanitize).toList();
            LOG.warn("Production readiness — {} encrypted value(s) could not be read with this DB_ENCRYPTION key in either "
                            + "the current or the legacy format (a changed key, an altered value, or plaintext awaiting "
                            + "HELIX_DB_ENCRYPTION_MIGRATE_PLAINTEXT); reading them fails:\n  - {}{}",
                    result.unreadable().size(), String.join("\n  - ", named),
                    result.unreadable().size() > MAX_NAMED_ROWS ? "\n  - …" : "");
        }
        failedColumns.set(result.failedColumns().size());
        if (!result.failedColumns().isEmpty()) {
            // Fallback stays on: a failed column may still hold legacy TOTP secrets or keys that must keep reading.
            AttributeEncryption.setLegacyFallback(true);
            readiness.ifAvailable(check -> check.warnAfterStartup("the legacy AES/ECB re-encryption failed for "
                    + String.join(", ", result.failedColumns()) + "; the legacy format (no integrity check) is still "
                    + "read until a start migrates them (see the ERROR above)"));
            return;
        }
        AttributeEncryption.setLegacyFallback(allowLegacy);
        if (allowLegacy) {
            LOG.warn("Production readiness — HELIX_DB_ENCRYPTION_ALLOW_LEGACY=true: the legacy AES/ECB format is still "
                    + "read. It has no integrity check; unset it once no legacy rows remain.");
        }
    }

    /** A column's SQL failure, carried out of the transaction callback. */
    private static final class ColumnFailure extends RuntimeException {
        ColumnFailure(final SQLException cause) {
            super(cause);
        }
    }
}
