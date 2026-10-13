/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.transaction;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.helixiam.common.startup.DeploymentProfile;
import io.helixiam.persistence.security.AttributeEncryption;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.testcontainers.containers.PostgreSQLContainer;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Production readiness item 3: the shared store contract (including the 20-thread races) against
 * {@link JdbcWalletTransactionStore} on a real PostgreSQL ({@code postgres:16-alpine}, the Flyway schema), plus what
 * only the table has: what a row dump reveals, the encryption rule and the sweep of expired rows.
 */
class JdbcWalletTransactionStoreTest extends AbstractWalletTransactionStoreTest {

    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");
    static final HikariDataSource DATA_SOURCE;
    static final JdbcTemplate JDBC;
    static final DataSourceTransactionManager TRANSACTIONS;

    static {
        POSTGRES.start();
        final HikariConfig config = new HikariConfig();
        config.setJdbcUrl(POSTGRES.getJdbcUrl());
        config.setUsername(POSTGRES.getUsername());
        config.setPassword(POSTGRES.getPassword());
        config.setMaximumPoolSize(25); // the 20-thread races
        config.setAutoCommit(false);   // like the server's pool: every write must commit in its own transaction
        DATA_SOURCE = new HikariDataSource(config);
        Flyway.configure().dataSource(DATA_SOURCE).locations("classpath:db/migration").load().migrate();
        JDBC = new JdbcTemplate(DATA_SOURCE);
        TRANSACTIONS = new DataSourceTransactionManager(DATA_SOURCE);
    }

    static final AttributeEncryption ENCRYPTION = new AttributeEncryption("0123456789abcdef0123456789abcdef");

    @AfterAll
    static void closePool() {
        DATA_SOURCE.close();
    }

    @Override
    WalletTransactionStore newStore(final Clock clock) {
        truncate();
        return new JdbcWalletTransactionStore(JDBC, TRANSACTIONS, ENCRYPTION, DeploymentProfile.production(), clock);
    }

    private static void truncate() {
        new org.springframework.transaction.support.TransactionTemplate(TRANSACTIONS)
                .executeWithoutResult(s -> JDBC.update("TRUNCATE wallet_transaction"));
    }

    private static int rows() {
        return JDBC.queryForObject("SELECT count(*) FROM wallet_transaction", Integer.class);
    }

    /** Every column of every row, as one list of strings. */
    private static List<String> dump() {
        final List<String> all = new ArrayList<>();
        for (final Map<String, Object> row : JDBC.queryForList("SELECT * FROM wallet_transaction")) {
            row.forEach((column, value) -> {
                all.add(column);
                all.add(String.valueOf(value));
            });
        }
        return all;
    }

    @Test
    void aRowDump_revealsNoBearerSecret_noPrivateKey_andNoIdentity() {
        final Verified v = verified();
        final WalletTransaction tx = v.tx();
        final WalletTransaction fetchedOnly = requestFetched(); // still holds its private key
        final WalletTransaction cross = verifiedCrossDevice();
        final String issued = store.issueResponseCode(cross.transactionId(), cross.browserBindingHash())
                .orElseThrow();

        final List<String> dump = dump();

        final String privateD = "Hndv7ZZjs_ke8o9zXYo3iq-Yr8SewI5vrqd0pAvEPqg";
        for (final String entry : dump) {
            assertThat(entry).isNotNull()
                    .doesNotContain(v.code(), tx.sameDeviceRequestId(), tx.crossDeviceRequestId(), tx.responseId(),
                            fetchedOnly.sameDeviceRequestId(), fetchedOnly.crossDeviceRequestId(),
                            fetchedOnly.responseId(), issued, privateD, "Erika");
        }
        // The lookups are by SHA-256, as in Redis.
        assertThat(dump).contains(SecretHash.of(issued), SecretHash.of(v.code()),
                SecretHash.of(tx.sameDeviceRequestId()), SecretHash.of(tx.crossDeviceRequestId()),
                SecretHash.of(tx.responseId()));
        // ...and the store still reads everything back.
        final WalletTransaction read = store.byTransactionId(fetchedOnly.transactionId()).orElseThrow();
        assertThat(read.encryptionJwkJson()).isEqualTo(JWK);
        assertThat(read.crossDeviceRequestId()).isEqualTo(fetchedOnly.crossDeviceRequestId());
        assertThat(read.responseId()).isEqualTo(fetchedOnly.responseId());
    }

    @Test
    void withoutDbEncryption_createIsRefusedOutsideDev_andAllowedInDev() {
        truncate();
        final AttributeEncryption none = new AttributeEncryption(null);
        final WalletTransactionStore production =
                new JdbcWalletTransactionStore(JDBC, TRANSACTIONS, none, DeploymentProfile.production(), clock);
        final WalletTransaction tx = newTransaction();

        assertThatThrownBy(() -> production.create(tx)).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("DB_ENCRYPTION");
        assertThat(rows()).isZero();

        final WalletTransactionStore dev =
                new JdbcWalletTransactionStore(JDBC, TRANSACTIONS, none, DeploymentProfile.development(), clock);
        dev.create(tx);
        assertThat(dev.byTransactionId(tx.transactionId()).orElseThrow().encryptionJwkJson()).isEqualTo(JWK);
    }

    @Test
    void aRowEncryptedUnderAnotherKey_failsClosed() {
        final WalletTransaction tx = created();
        final WalletTransactionStore otherKey = new JdbcWalletTransactionStore(JDBC, TRANSACTIONS,
                new AttributeEncryption("fedcba9876543210fedcba9876543210"), DeploymentProfile.production(), clock);

        assertThatThrownBy(() -> otherKey.byTransactionId(tx.transactionId())).isInstanceOf(RuntimeException.class);
    }

    @Test
    void sweep_deletesExpiredRowsOnly_andAnExpiredRowIsAbsentBeforeTheSweep() {
        final WalletTransaction old = created();
        clock.advance(Duration.ofSeconds(200));
        final WalletTransaction young = created();
        clock.advance(Duration.ofSeconds(100)); // old is now at its expiry, young is not

        assertThat(store.byTransactionId(old.transactionId())).as("expired reads as absent").isEmpty();
        assertThat(rows()).isEqualTo(2);

        assertThat(((JdbcWalletTransactionStore) store).sweep()).isEqualTo(1);

        assertThat(rows()).isEqualTo(1);
        assertThat(store.byTransactionId(young.transactionId())).isPresent();
    }
}
