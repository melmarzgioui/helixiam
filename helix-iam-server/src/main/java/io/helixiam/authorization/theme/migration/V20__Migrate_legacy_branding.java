/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.migration;

import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

import java.util.Set;
import java.util.function.Consumer;

/**
 * Flyway V20 (spec §7): moves the legacy realm and organization branding columns into the theme layers created by
 * V19, validating every value ({@link LegacyBrandingMigrator}); invalid legacy custom CSS is dropped and logged.
 *
 * <p>Registered as a Spring bean ({@link ThemeMigrationConfiguration}) so it receives the configured image-origin
 * allowlist; Spring Boot hands {@code JavaMigration} beans to Flyway. It lives outside {@code db/migration} so
 * Flyway's classpath scan does not also pick it up.
 */
@SuppressWarnings("checkstyle:TypeName")
public class V20__Migrate_legacy_branding extends BaseJavaMigration {

    private final Set<String> allowedImageOrigins;
    private final Consumer<String> warnings;

    public V20__Migrate_legacy_branding(final Set<String> allowedImageOrigins, final Consumer<String> warnings) {
        this.allowedImageOrigins = allowedImageOrigins;
        this.warnings = warnings;
    }

    @Override
    public void migrate(final Context context) throws Exception {
        new LegacyBrandingMigrator(allowedImageOrigins, warnings).migrate(context.getConnection());
    }
}
