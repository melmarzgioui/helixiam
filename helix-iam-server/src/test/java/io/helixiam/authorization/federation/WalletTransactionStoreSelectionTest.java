/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.federation.wallet.transaction.InMemoryWalletTransactionStore;
import io.helixiam.authorization.federation.wallet.transaction.JdbcWalletTransactionStore;
import io.helixiam.authorization.federation.wallet.transaction.RedisWalletTransactionStore;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransactionStore;
import io.helixiam.common.startup.DeploymentProfile;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/** Which {@link WalletTransactionStore} {@link FederationConfig} wires, and when it warns about replicas. */
class WalletTransactionStoreSelectionTest {

    /** No datasource: what a context without the database has. */
    private final ApplicationContextRunner withoutDatabase = new ApplicationContextRunner()
            .withUserConfiguration(FederationConfig.WalletTransactionStores.class)
            .withBean(RedisConnectionFactory.class, () -> mock(RedisConnectionFactory.class))
            .withBean(DeploymentProfile.class, DeploymentProfile::production)
            .withPropertyValues("database.encryption=0123456789abcdef0123456789abcdef");

    /** The server: it always has its PostgreSQL datasource. */
    private final ApplicationContextRunner runner = withoutDatabase
            .withBean(JdbcTemplate.class, () -> mock(JdbcTemplate.class))
            .withBean(PlatformTransactionManager.class, () -> mock(PlatformTransactionManager.class));

    @Test
    void sessionStoreRedis_selectsRedis() {
        runner.withPropertyValues("helix.iam.session-store=redis", "helix.iam.token-store=queue").run(ctx ->
                assertThat(ctx).getBean(WalletTransactionStore.class).isInstanceOf(RedisWalletTransactionStore.class));
    }

    @Test
    void tokenStoreRedis_withoutTheQueueSessionStore_selectsRedis() {
        runner.withPropertyValues("helix.iam.token-store=redis").run(ctx ->
                assertThat(ctx).getBean(WalletTransactionStore.class).isInstanceOf(RedisWalletTransactionStore.class));
    }

    @Test
    void theQueueSessionStore_selectsPostgres_evenWithARedisTokenStore() {
        runner.withPropertyValues("helix.iam.session-store=queue", "helix.iam.token-store=redis").run(ctx ->
                assertThat(ctx).getBean(WalletTransactionStore.class).isInstanceOf(JdbcWalletTransactionStore.class));
    }

    @Test
    void neitherRedis_selectsPostgres() {
        runner.withPropertyValues("helix.iam.session-store=queue", "helix.iam.token-store=queue").run(ctx -> {
            assertThat(ctx).hasSingleBean(WalletTransactionStore.class);
            assertThat(ctx).getBean(WalletTransactionStore.class).isInstanceOf(JdbcWalletTransactionStore.class);
        });
        runner.run(ctx ->
                assertThat(ctx).getBean(WalletTransactionStore.class).isInstanceOf(JdbcWalletTransactionStore.class));
    }

    @Test
    void theInMemoryStore_onlyWhenAskedFor() {
        runner.withPropertyValues("helix.iam.session-store=queue", "helix.wallet.transaction-store=memory").run(ctx ->
                assertThat(ctx).getBean(WalletTransactionStore.class)
                        .isInstanceOf(InMemoryWalletTransactionStore.class));
    }

    @Test
    void noRedisNoDatabaseAndNoExplicitMemory_failsAtStartup_neverFallsBackToMemory() {
        withoutDatabase.withPropertyValues("helix.iam.session-store=queue").run(ctx ->
                assertThat(ctx).hasFailed().getFailure().hasStackTraceContaining("helix.wallet.transaction-store"));
    }

    @Test
    void anUnknownStoreName_failsAtStartup() {
        runner.withPropertyValues("helix.wallet.transaction-store=etcd").run(ctx -> assertThat(ctx).hasFailed());
    }
}
