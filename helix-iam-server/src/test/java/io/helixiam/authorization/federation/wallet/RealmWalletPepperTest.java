/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.helixiam.authorization.controller.admin.io.RealmExportService;
import io.helixiam.common.startup.DeploymentProfile;
import io.helixiam.e2e.AbstractE2eTest;
import io.helixiam.e2e.E2eSeed;
import io.helixiam.persistence.security.AttributeEncryption;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Task 21a: {@link RealmWalletPepper} — the per-realm 256-bit HMAC pepper of the wallet subject, created lazily,
 * stored encrypted ({@code DB_ENCRYPTION}), race-safe, never exported. Runs against the shared e2e context, so both
 * the Flyway (V77) and, with {@code -Dhelix.e2e.schema=sql-init}, the schema.sql path create the table.
 */
class RealmWalletPepperTest extends AbstractE2eTest {

    private static final String KEY = "0123456789abcdef0123456789abcdef";

    private JdbcTemplate jdbc;
    private PlatformTransactionManager transactions;
    private RealmWalletPepper peppers;
    private String realm;

    @BeforeEach
    void setUp() {
        jdbc = context.getBean(JdbcTemplate.class);
        transactions = context.getBean(PlatformTransactionManager.class);
        peppers = context.getBean(RealmWalletPepper.class);
        realm = E2eSeed.unique("wsubj"); // no "pepper" in the id: the export test looks for that word
    }

    private RealmWalletPepper store(final String encryptionKey, final DeploymentProfile profile) {
        return new RealmWalletPepper(jdbc, transactions, new AttributeEncryption(encryptionKey), profile);
    }

    private int rows(final String realmId) {
        return new TransactionTemplate(transactions).execute(s -> jdbc.queryForObject(
                "SELECT count(*) FROM realm_wallet_pepper WHERE realm_id = ?", Integer.class, realmId));
    }

    private String storedColumn(final String realmId) {
        return new TransactionTemplate(transactions).execute(s -> jdbc.queryForObject(
                "SELECT pepper FROM realm_wallet_pepper WHERE realm_id = ?", String.class, realmId));
    }

    @Test
    void createdLazily_256Bits_stableAcrossCallsAndInstances() {
        assertThat(rows(realm)).isZero();

        final byte[] first = peppers.pepper(realm);

        assertThat(first).hasSize(32);
        assertThat(rows(realm)).isEqualTo(1);
        assertThat(peppers.pepper(realm)).isEqualTo(first);
        assertThat(store(KEY, DeploymentProfile.production()).pepper(realm)).isEqualTo(first);
    }

    @Test
    void everyRealmHasItsOwnPepper() {
        assertThat(peppers.pepper(realm)).isNotEqualTo(peppers.pepper(realm + "-other"));
    }

    @Test
    void storedEncryptedAtRest() {
        final byte[] pepper = peppers.pepper(realm);
        final String column = storedColumn(realm);
        final String plain = Base64.getEncoder().encodeToString(pepper);

        assertThat(column).isNotEqualTo(plain).doesNotContain(plain)
                .doesNotContain(HexFormat.of().formatHex(pepper));
        assertThat(new AttributeEncryption(KEY).convertToEntityAttribute(column)).isEqualTo(plain);
    }

    @Test
    void concurrentFirstUse_yieldsOnePepper() throws Exception {
        final int threads = 8;
        final ExecutorService pool = Executors.newFixedThreadPool(threads);
        final CountDownLatch start = new CountDownLatch(1);
        try {
            final List<Future<byte[]>> results = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                // separate instances, as on separate replicas
                final RealmWalletPepper instance = store(KEY, DeploymentProfile.production());
                final Callable<byte[]> call = () -> {
                    start.await();
                    return instance.pepper(realm);
                };
                results.add(pool.submit(call));
            }
            start.countDown();
            final byte[] first = results.get(0).get(30, TimeUnit.SECONDS);
            for (final Future<byte[]> result : results) {
                assertThat(result.get(30, TimeUnit.SECONDS)).isEqualTo(first);
            }
        } finally {
            pool.shutdownNow();
        }
        assertThat(rows(realm)).isEqualTo(1);
    }

    @Test
    void withoutDbEncryption_creationIsRefusedOutsideDev_andAllowedInDev() {
        assertThatThrownBy(() -> store(null, DeploymentProfile.production()).pepper(realm))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("DB_ENCRYPTION");
        assertThat(rows(realm)).isZero();

        final byte[] devPepper = store(null, DeploymentProfile.development()).pepper(realm);

        assertThat(devPepper).hasSize(32);
        assertThat(rows(realm)).isEqualTo(1);
    }

    @Test
    void aBlankRealmIsRefused() {
        assertThatThrownBy(() -> peppers.pepper(" ")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> peppers.pepper(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void thePepperIsNeverInTheRealmExport() throws Exception {
        new E2eSeed(context).realm(realm);
        final byte[] pepper = peppers.pepper(realm);

        final String exported = new ObjectMapper().findAndRegisterModules()
                .writeValueAsString(context.getBean(RealmExportService.class).export(realm));

        assertThat(exported).contains(realm)
                .doesNotContain(Base64.getEncoder().encodeToString(pepper))
                .doesNotContain(Base64.getUrlEncoder().withoutPadding().encodeToString(pepper))
                .doesNotContain(HexFormat.of().formatHex(pepper))
                .doesNotContain(storedColumn(realm))
                .doesNotContainIgnoringCase("pepper");
    }
}
