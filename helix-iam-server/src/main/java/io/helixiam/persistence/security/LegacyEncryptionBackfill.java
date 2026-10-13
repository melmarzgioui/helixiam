/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.persistence.security;

import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
import java.util.List;

/**
 * L5: at every startup (Flyway and {@code schema.sql} paths alike), re-encrypts any value still in the legacy AES/ECB
 * format ({@link LegacyEncryptionMigrator}), then turns the converter's ECB fallback off unless
 * {@code HELIX_DB_ENCRYPTION_ALLOW_LEGACY=true}. Idempotent: after the first run only current-format rows remain, so a
 * later start rewrites nothing. Rows it cannot read are named (table, column, id) in a production-readiness WARN. If the
 * run itself fails (a database error), the fallback stays on so nothing that read yesterday breaks today, and the next
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

    public LegacyEncryptionBackfill(final DataSource dataSource, final PlatformTransactionManager transactionManager,
                                    @Value("${database.encryption:#{null}}") final String encryptionKey,
                                    @Value("${helix.security.db-encryption.allow-legacy:false}") final boolean allowLegacy) {
        this.dataSource = dataSource;
        this.tx = new TransactionTemplate(transactionManager);
        this.encryption = new AttributeEncryption(encryptionKey);
        this.allowLegacy = allowLegacy;
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

    /** One run: re-encrypt, report what could not be read, then set the fallback. */
    public LegacyEncryptionMigrator.Result runOnce() {
        final LegacyEncryptionMigrator.Result result = tx.execute(status -> {
            final Connection c = DataSourceUtils.getConnection(dataSource);
            try {
                return new LegacyEncryptionMigrator(encryption).migrate(c);
            } catch (final SQLException e) {
                throw new IllegalStateException(e);
            } finally {
                DataSourceUtils.releaseConnection(c, dataSource);
            }
        });
        if (result != null && !result.unreadable().isEmpty()) {
            final List<String> named = result.unreadable().stream().limit(MAX_NAMED_ROWS)
                    .map(LogSafe::sanitize).toList();
            LOG.warn("Production readiness — {} encrypted value(s) could not be read with this DB_ENCRYPTION key in either "
                            + "the current or the legacy format (a changed key, an altered value, or plaintext awaiting "
                            + "HELIX_DB_ENCRYPTION_MIGRATE_PLAINTEXT); reading them fails:\n  - {}{}",
                    result.unreadable().size(), String.join("\n  - ", named),
                    result.unreadable().size() > MAX_NAMED_ROWS ? "\n  - …" : "");
        }
        AttributeEncryption.setLegacyFallback(allowLegacy);
        if (allowLegacy) {
            LOG.warn("Production readiness — HELIX_DB_ENCRYPTION_ALLOW_LEGACY=true: the legacy AES/ECB format is still "
                    + "read. It has no integrity check; unset it once no legacy rows remain.");
        }
        return result;
    }
}
