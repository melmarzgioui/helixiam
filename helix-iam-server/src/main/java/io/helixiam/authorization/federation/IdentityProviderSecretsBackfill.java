/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.common.log.LogSafe;
import io.helixiam.persistence.security.AttributeEncryption;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;

/**
 * The {@code schema.sql} path's counterpart of Flyway V75.1 (Task 4, security): when Flyway is disabled, moves any
 * identity-provider secret still in the plaintext {@code config_json} into the encrypted {@code secret_json} at startup
 * ({@link IdentityProviderSecretsMigrator}). Idempotent: moved secrets are gone from {@code config_json}, so later starts
 * do nothing. Until it has run, the service still reads a legacy secret from {@code config_json} and the admin API
 * never returns it.
 */
@Component
@ConditionalOnProperty(name = "spring.flyway.enabled", havingValue = "false")
public class IdentityProviderSecretsBackfill implements ApplicationRunner {

    private static final Logger LOG = LogManager.getLogger(IdentityProviderSecretsBackfill.class);

    private final DataSource dataSource;
    private final TransactionTemplate tx;
    private final AttributeEncryption encryption;

    public IdentityProviderSecretsBackfill(final DataSource dataSource,
                                           final PlatformTransactionManager transactionManager,
                                           @Value("${database.encryption:#{null}}") final String encryptionKey) {
        this.dataSource = dataSource;
        this.tx = new TransactionTemplate(transactionManager);
        this.encryption = new AttributeEncryption(encryptionKey);
    }

    @Override
    public void run(final ApplicationArguments args) {
        try {
            tx.execute(status -> {
                final Connection c = DataSourceUtils.getConnection(dataSource);
                try {
                    return new IdentityProviderSecretsMigrator(encryption).migrate(c);
                } catch (final SQLException e) {
                    throw new IllegalStateException(e);
                } finally {
                    DataSourceUtils.releaseConnection(c, dataSource);
                }
            });
        } catch (final RuntimeException e) {
            // Never block startup: the legacy secrets stay where they are and are retried on the next start.
            LOG.warn("Identity-provider secrets backfill failed; will retry on next start: {}",
                    LogSafe.sanitize(e.getMessage()));
        }
    }
}
