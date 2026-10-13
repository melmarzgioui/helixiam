/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import io.helixiam.persistence.security.AttributeEncryption;
import io.helixiam.persistence.security.LegacyEncryptionBackfill;
import io.helixiam.persistence.security.LegacyEncryptionMigrator;
import io.helixiam.testsupport.LogCapture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * L5: the one-time re-encryption of the legacy AES/ECB format, against the real schema. A legacy row of an
 * {@code AttributeEncryption} column is rewritten in the current AES-GCM format; a row that cannot be read is skipped
 * and reported by id; a second run changes nothing; afterwards the ECB fallback is off (HELIX_DB_ENCRYPTION_ALLOW_LEGACY
 * defaults to false), so a legacy value fails closed.
 */
class LegacyEncryptionMigrationE2eTest extends AbstractE2eTest {

    private static final String KEY = "0123456789abcdef0123456789abcdef"; // AbstractE2eTest's database.encryption
    private static final String OTHER_KEY = "fedcba9876543210fedcba9876543210";
    private static final String SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

    private final String legacyUser = "legacy-hotp-" + UUID.randomUUID();
    private final String unreadableUser = "unreadable-hotp-" + UUID.randomUUID();

    private JdbcTemplate jdbc() {
        return context.getBean(JdbcTemplate.class);
    }

    /** The pool does not auto-commit: writes run in a transaction. */
    private void write(final String sql, final Object... args) {
        new org.springframework.transaction.support.TransactionTemplate(
                context.getBean(org.springframework.transaction.PlatformTransactionManager.class))
                .executeWithoutResult(tx -> jdbc().update(sql, args));
    }

    @AfterEach
    void cleanUp() {
        write("DELETE FROM mfa_hotp WHERE user_id IN (?, ?)", legacyUser, unreadableUser);
        AttributeEncryption.setLegacyFallback(false);
    }

    private static String legacyEcb(final String key, final String value) throws Exception {
        final Cipher legacy = Cipher.getInstance("AES");
        legacy.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES"));
        return Base64.getEncoder().encodeToString(legacy.doFinal(value.getBytes(StandardCharsets.UTF_8)));
    }

    private String storedSecret(final String userId) {
        return jdbc().queryForObject("SELECT secret FROM mfa_hotp WHERE user_id = ?", String.class, userId);
    }

    @Test
    void aLegacyRowIsReEncrypted_anUnreadableOneReportedById_andTheRunIsIdempotent() throws Exception {
        final String legacy = legacyEcb(KEY, SECRET);
        final String unreadable = legacyEcb(OTHER_KEY, SECRET); // ECB-shaped, but another key's
        write("INSERT INTO mfa_hotp (user_id, secret, counter) VALUES (?, ?, 0)", legacyUser, legacy);
        write("INSERT INTO mfa_hotp (user_id, secret, counter) VALUES (?, ?, 0)", unreadableUser, unreadable);
        final LegacyEncryptionBackfill backfill = context.getBean(LegacyEncryptionBackfill.class);

        final LegacyEncryptionMigrator.Result first;
        try (LogCapture migrator = LogCapture.of(LegacyEncryptionMigrator.class);
             LogCapture readiness = LogCapture.of(LegacyEncryptionBackfill.class)) {
            first = backfill.runOnce();
            final String text = migrator.text() + "\n" + readiness.text();
            assertThat(migrator.text()).contains(legacyUser).contains(unreadableUser);
            assertThat(readiness.text()).contains("mfa_hotp.secret " + unreadableUser);
            assertThat(text).doesNotContain(SECRET).doesNotContain(unreadable).doesNotContain(legacy);
        }

        assertThat(first.reEncrypted()).isEqualTo(1);
        // (other tests of the shared database may leave rows under another key; they are reported too)
        assertThat(first.unreadable()).contains("mfa_hotp.secret " + unreadableUser)
                .filteredOn(row -> row.startsWith("mfa_hotp.")).hasSize(1);
        final String rewritten = storedSecret(legacyUser);
        assertThat(rewritten).isNotEqualTo(legacy);
        assertThat(storedSecret(unreadableUser)).as("an unreadable row is left as it is").isEqualTo(unreadable);
        // Afterwards the fallback is off: the rewritten row reads, a legacy value fails closed.
        assertThat(AttributeEncryption.legacyFallbackEnabled()).isFalse();
        final AttributeEncryption enc = new AttributeEncryption(KEY, false);
        assertThat(enc.convertToEntityAttribute(rewritten)).isEqualTo(SECRET);
        assertThatThrownBy(() -> enc.convertToEntityAttribute(legacy)).isInstanceOf(IllegalStateException.class);

        final LegacyEncryptionMigrator.Result second = backfill.runOnce();
        assertThat(second.reEncrypted()).isZero();
        assertThat(storedSecret(legacyUser)).isEqualTo(rewritten);
    }

    /**
     * One column failing (here: a table that does not exist) is its own transaction: it is logged at ERROR by table and
     * column, every other column is still migrated, the ECB fallback stays on (legacy reads keep working), and the
     * condition shows in the production-readiness check and as a metric.
     */
    @Test
    void aFailingColumn_isReported_theOthersAreStillMigrated_andTheFallbackStaysOn() throws Exception {
        final String legacy = legacyEcb(KEY, SECRET);
        write("INSERT INTO mfa_hotp (user_id, secret, counter) VALUES (?, ?, 0)", legacyUser, legacy);
        final LegacyEncryptionBackfill backfill = context.getBean(LegacyEncryptionBackfill.class);
        final java.util.List<LegacyEncryptionMigrator.EncryptedColumn> columns = java.util.List.of(
                new LegacyEncryptionMigrator.EncryptedColumn("no_such_table", "id", "secret"),
                new LegacyEncryptionMigrator.EncryptedColumn("mfa_hotp", "user_id", "secret"));

        final LegacyEncryptionMigrator.Result result;
        try (LogCapture log = LogCapture.of(LegacyEncryptionBackfill.class)) {
            result = backfill.runOnce(columns);
            assertThat(log.text()).contains("no_such_table.secret").doesNotContain(SECRET).doesNotContain(legacy);
        }

        assertThat(result.failedColumns()).containsExactly("no_such_table.secret");
        assertThat(result.reEncrypted()).isEqualTo(1);
        assertThat(storedSecret(legacyUser)).isNotEqualTo(legacy);
        assertThat(AttributeEncryption.legacyFallbackEnabled()).as("legacy reads keep working").isTrue();
        assertThat(context.getBean(io.helixiam.common.startup.ProductionReadinessCheck.class).lateWarnings())
                .anySatisfy(w -> assertThat(w).contains("no_such_table.secret"));
        assertThat(context.getBean(io.micrometer.core.instrument.MeterRegistry.class)
                .get("helix_db_encryption_legacy_failed_columns").gauge().value()).isEqualTo(1.0);

        // a clean run afterwards clears the condition
        backfill.runOnce();
        assertThat(context.getBean(io.micrometer.core.instrument.MeterRegistry.class)
                .get("helix_db_encryption_legacy_failed_columns").gauge().value()).isZero();
    }

    /** Rows are rewritten in id order, so two replicas booting together lock them in the same order (no deadlock). */
    @Test
    void rowsAreReEncryptedInIdOrder() throws Exception {
        final String later = "zz-" + legacyUser;
        final String earlier = "aa-" + legacyUser;
        write("INSERT INTO mfa_hotp (user_id, secret, counter) VALUES (?, ?, 0)", later, legacyEcb(KEY, SECRET));
        write("INSERT INTO mfa_hotp (user_id, secret, counter) VALUES (?, ?, 0)", earlier, legacyEcb(KEY, SECRET));
        try (LogCapture log = LogCapture.of(LegacyEncryptionMigrator.class)) {
            context.getBean(LegacyEncryptionBackfill.class).runOnce();
            final String text = log.text();
            assertThat(text.indexOf(earlier)).isNotNegative().isLessThan(text.indexOf(later));
        } finally {
            write("DELETE FROM mfa_hotp WHERE user_id IN (?, ?)", later, earlier);
        }
    }
}
