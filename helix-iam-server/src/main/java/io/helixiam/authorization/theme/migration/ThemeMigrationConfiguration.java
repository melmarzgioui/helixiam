/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.migration;

import io.helixiam.authorization.theme.ThemeService;
import org.flywaydb.core.api.migration.JavaMigration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Registers the theme data migration with Flyway (Spring Boot passes {@link JavaMigration} beans to Flyway). */
@Configuration(proxyBeanMethods = false)
public class ThemeMigrationConfiguration {

    @Bean
    public JavaMigration legacyBrandingMigration(
            @Value("${" + ThemeService.ALLOWED_IMAGE_ORIGINS + ":}") final String allowedImageOrigins) {
        return new V20__Migrate_legacy_branding(ThemeService.parseOrigins(allowedImageOrigins), null);
    }
}
