/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.federation.wallet.transaction.InMemoryWalletTransactionStore;
import io.helixiam.authorization.federation.wallet.transaction.RedisWalletTransactionStore;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransactionStore;
import io.helixiam.common.startup.DeploymentProfile;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.data.redis.connection.RedisConnectionFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/** Which {@link WalletTransactionStore} {@link FederationConfig} wires, and when it warns about replicas. */
class WalletTransactionStoreSelectionTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(FederationConfig.WalletTransactionStores.class)
            .withBean(RedisConnectionFactory.class, () -> mock(RedisConnectionFactory.class))
            .withBean(DeploymentProfile.class, DeploymentProfile::production)
            .withPropertyValues("database.encryption=0123456789abcdef0123456789abcdef");

    @Test
    void sessionStoreRedis_selectsRedis() {
        runner.withPropertyValues("helix.iam.session-store=redis", "helix.iam.token-store=queue").run(ctx ->
                assertThat(ctx).getBean(WalletTransactionStore.class).isInstanceOf(RedisWalletTransactionStore.class));
    }

    @Test
    void tokenStoreRedis_selectsRedis() {
        runner.withPropertyValues("helix.iam.session-store=queue", "helix.iam.token-store=redis").run(ctx ->
                assertThat(ctx).getBean(WalletTransactionStore.class).isInstanceOf(RedisWalletTransactionStore.class));
    }

    @Test
    void neitherRedis_selectsInMemory() {
        runner.withPropertyValues("helix.iam.session-store=queue", "helix.iam.token-store=queue").run(ctx -> {
            assertThat(ctx).hasSingleBean(WalletTransactionStore.class);
            assertThat(ctx).getBean(WalletTransactionStore.class)
                    .isInstanceOf(InMemoryWalletTransactionStore.class);
        });
    }

    @Test
    void inMemoryWarns_onlyWithThePostgresSessionStore_andNeverInDev() {
        // No replica count reaches the server; session-store=queue (PostgreSQL) is the multi-replica signal.
        final DeploymentProfile production = DeploymentProfile.production();
        assertThat(FederationConfig.WalletTransactionStores.warnsAboutReplicas("queue", production)).isTrue();
        assertThat(FederationConfig.WalletTransactionStores.warnsAboutReplicas("QUEUE", production)).isTrue();
        assertThat(FederationConfig.WalletTransactionStores.warnsAboutReplicas("", production)).isFalse();
        assertThat(FederationConfig.WalletTransactionStores.warnsAboutReplicas(null, production)).isFalse();
        // dev defaults session-store to queue and runs one process: no WARN.
        assertThat(FederationConfig.WalletTransactionStores.warnsAboutReplicas("queue",
                DeploymentProfile.development())).isFalse();
    }
}
