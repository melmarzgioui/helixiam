/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.config;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM PROD-4 (versioned migrations): pins the Flyway migration contract so the opt-in schema
 * path stays trustworthy. The V1 baseline must (a) exist under db/migration with a valid Flyway
 * version-script name, and (b) carry the canonical schema verbatim — its SQL body must equal
 * schema.sql (the legacy spring.sql.init bootstrap), so the two schema paths can never drift. Runs
 * offline (pure resource checks; no database).
 */
class FlywayBaselineMigrationTest {

    private static final Path RESOURCES = Path.of("src/main/resources");
    private static final Path MIGRATIONS = RESOURCES.resolve("db/migration");

    @Test
    void baselineMigrationExistsWithValidFlywayName() throws Exception {
        try (Stream<Path> files = Files.list(MIGRATIONS)) {
            final List<String> names = files.map(p -> p.getFileName().toString()).sorted().toList();
            assertThat(names).contains("V1__baseline_schema.sql");
            // Every script follows Flyway's V<version>__<description>.sql convention.
            assertThat(names).allMatch(n -> n.matches("V\\d+(\\.\\d+)*__[A-Za-z0-9_]+\\.sql"));
        }
    }

    @Test
    void migrationsCreateExactlyTheSameTablesAsCanonicalSchema() throws Exception {
        // No-drift invariant: the Flyway migration chain and the legacy schema.sql must define the SAME set
        // of tables. schema.sql is the full current schema, so the contract is against the UNION of ALL
        // V*.sql migrations (V1 baseline + every forward migration that adds a table, e.g. workload identity
        // and agent identity), not V1 alone. Table-set parity across the whole chain is the real guard.
        final var schemaTables = createTableNames(Files.readString(RESOURCES.resolve("schema.sql"), StandardCharsets.UTF_8));

        final TreeSet<String> migrationTables = new TreeSet<>();
        try (Stream<Path> files = Files.list(MIGRATIONS)) {
            for (final Path migration : files.filter(p -> p.getFileName().toString().endsWith(".sql")).toList()) {
                migrationTables.addAll(createTableNames(Files.readString(migration, StandardCharsets.UTF_8)));
            }
        }

        assertThat(migrationTables).isEqualTo(schemaTables);
        assertThat(migrationTables).contains("user_in_role", "tenant_user", "user_credentials"); // sanity
    }

    /** Every {@code CREATE TABLE [IF NOT EXISTS] <name>} target in a SQL script, as a sorted set. */
    private static TreeSet<String> createTableNames(final String sql) {
        final Matcher m = Pattern
                .compile("CREATE TABLE\\s+(?:IF NOT EXISTS\\s+)?\"?([A-Za-z0-9_]+)\"?", Pattern.CASE_INSENSITIVE)
                .matcher(sql);
        final TreeSet<String> names = new TreeSet<>();
        while (m.find()) {
            names.add(m.group(1).toLowerCase());
        }
        return names;
    }
}
