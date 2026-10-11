/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.persistence.security.AttributeEncryption;
import org.flywaydb.core.api.migration.JavaMigration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Registers the identity-provider secrets data migration with Flyway (Spring Boot passes {@link JavaMigration} beans to
 * Flyway), keyed like the JPA column converter ({@code database.encryption} / {@code DB_ENCRYPTION}).
 */
@Configuration(proxyBeanMethods = false)
public class IdentityProviderSecretsMigrationConfiguration {

    @Bean
    public JavaMigration identityProviderSecretsMigration(
            @Value("${database.encryption:#{null}}") final String encryptionKey) {
        return new V75_1__Move_identity_provider_secrets(new AttributeEncryption(encryptionKey));
    }
}
