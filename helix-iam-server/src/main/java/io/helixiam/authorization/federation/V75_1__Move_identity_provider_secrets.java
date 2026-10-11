/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.persistence.security.AttributeEncryption;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

/**
 * Flyway V75.1 (Task 4, security): after V75 adds {@code identity_provider.secret_json}, moves every identity-provider
 * secret out of the plaintext {@code config_json} into it, encrypted with {@code DB_ENCRYPTION}
 * ({@link IdentityProviderSecretsMigrator}).
 *
 * <p>Registered as a Spring bean ({@link IdentityProviderSecretsMigrationConfiguration}) so it receives the configured
 * encryption key; Spring Boot hands {@code JavaMigration} beans to Flyway. It lives outside {@code db/migration} so
 * Flyway's classpath scan does not also pick it up.
 */
@SuppressWarnings("checkstyle:TypeName")
public class V75_1__Move_identity_provider_secrets extends BaseJavaMigration {

    private final AttributeEncryption encryption;

    public V75_1__Move_identity_provider_secrets(final AttributeEncryption encryption) {
        this.encryption = encryption;
    }

    @Override
    public void migrate(final Context context) throws Exception {
        new IdentityProviderSecretsMigrator(encryption).migrate(context.getConnection());
    }
}
