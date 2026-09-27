/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.migration;

import io.helixiam.authorization.theme.ThemeService;
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
 * The {@code schema.sql} path's counterpart of Flyway V20: when Flyway is disabled, moves any remaining legacy
 * branding columns into the theme layers at startup (same rules, {@link LegacyBrandingMigrator}). Idempotent — the
 * legacy columns are emptied once moved, so later starts do nothing.
 */
@Component
@ConditionalOnProperty(name = "spring.flyway.enabled", havingValue = "false")
public class LegacyBrandingBackfill implements ApplicationRunner {

    private static final Logger LOG = LogManager.getLogger(LegacyBrandingBackfill.class);

    private final DataSource dataSource;
    private final TransactionTemplate tx;
    private final String allowedImageOrigins;

    public LegacyBrandingBackfill(final DataSource dataSource, final PlatformTransactionManager transactionManager,
                                  @Value("${" + ThemeService.ALLOWED_IMAGE_ORIGINS + ":}") final String allowedImageOrigins) {
        this.dataSource = dataSource;
        this.tx = new TransactionTemplate(transactionManager);
        this.allowedImageOrigins = allowedImageOrigins;
    }

    @Override
    public void run(final ApplicationArguments args) {
        try {
            final LegacyBrandingMigrator.Result result = tx.execute(status -> {
                final Connection c = DataSourceUtils.getConnection(dataSource);
                try {
                    return new LegacyBrandingMigrator(ThemeService.parseOrigins(allowedImageOrigins), null).migrate(c);
                } catch (final SQLException e) {
                    throw new IllegalStateException(e);
                } finally {
                    DataSourceUtils.releaseConnection(c, dataSource);
                }
            });
            if (result != null && (result.realms() > 0 || result.organizations() > 0)) {
                LOG.info("Moved legacy branding into theme layers: {} realm(s), {} organization(s)",
                        result.realms(), result.organizations());
            }
        } catch (final RuntimeException e) {
            // Never block startup: the legacy columns stay and are retried on the next start.
            LOG.warn("Legacy branding backfill failed; will retry on next start: {}",
                    io.helixiam.common.log.LogSafe.sanitize(e.getMessage()));
        }
    }
}
