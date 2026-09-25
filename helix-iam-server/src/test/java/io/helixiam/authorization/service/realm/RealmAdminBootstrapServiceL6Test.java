/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.realm;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * L6: when {@code helix.admin.password-file} is set, a generated bootstrap admin password is written to
 * that file with owner-only (0600) permissions instead of being left in the logs.
 */
class RealmAdminBootstrapServiceL6Test {

    // resolveBootstrapPassword() touches none of the repositories, so nulls are fine here.
    private static RealmAdminBootstrapService service(final String password, final String passwordFile) {
        return new RealmAdminBootstrapService(null, null, null, null, null, null, "admin", password, passwordFile);
    }

    @Test
    void generatedPasswordIsWrittenToA0600File(@TempDir final Path dir) throws Exception {
        final Path file = dir.resolve("admin-password");
        final String pw = service("", file.toString()).resolveBootstrapPassword();

        assertThat(pw).isNotBlank();
        assertThat(file).exists();
        assertThat(Files.readString(file).trim()).isEqualTo(pw);
        assertThat(Files.getPosixFilePermissions(file))
                .as("0600 permissions")
                .isEqualTo(PosixFilePermissions.fromString("rw-------"));
    }

    @Test
    void aConfiguredPasswordWins_andNoFileIsWritten(@TempDir final Path dir) {
        final Path file = dir.resolve("admin-password");
        assertThat(service("s3cret!", file.toString()).resolveBootstrapPassword()).isEqualTo("s3cret!");
        assertThat(file).doesNotExist();
    }

    @Test
    void withNoFileConfigured_aPasswordIsStillGenerated() {
        assertThat(service("", "").resolveBootstrapPassword()).isNotBlank();
    }
}
