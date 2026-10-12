/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.transaction;

import io.helixiam.common.startup.DeploymentProfile;
import io.helixiam.persistence.security.AttributeEncryption;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The shared store contract against {@link RedisWalletTransactionStore} on a real Redis ({@code redis:7-alpine}, the
 * same image and singleton pattern as {@code AbstractE2eTest}), plus what only Redis has: TTLs and what a key dump
 * reveals.
 */
class RedisWalletTransactionStoreTest extends AbstractWalletTransactionStoreTest {

    @SuppressWarnings("resource")
    static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);
    static final LettuceConnectionFactory FACTORY;
    static final StringRedisTemplate REDIS_TEMPLATE;

    static {
        REDIS.start();
        FACTORY = new LettuceConnectionFactory(new RedisStandaloneConfiguration(REDIS.getHost(),
                REDIS.getMappedPort(6379)));
        FACTORY.afterPropertiesSet();
        FACTORY.start();
        REDIS_TEMPLATE = new StringRedisTemplate(FACTORY);
    }

    static final AttributeEncryption ENCRYPTION = new AttributeEncryption("0123456789abcdef0123456789abcdef");

    @AfterAll
    static void stopFactory() {
        FACTORY.destroy();
    }

    @Override
    WalletTransactionStore newStore(final Clock clock) {
        flushAll();
        return new RedisWalletTransactionStore(FACTORY, ENCRYPTION, DeploymentProfile.production(), clock);
    }

    private static void flushAll() {
        REDIS_TEMPLATE.execute((org.springframework.data.redis.core.RedisCallback<Void>) connection -> {
            connection.serverCommands().flushAll();
            return null;
        });
    }

    private static Set<String> walletKeys() {
        return REDIS_TEMPLATE.keys("helix:wallet:*");
    }

    /** Every key, hash field, hash value and string value, as one list of strings. */
    private static List<String> dump() {
        final List<String> all = new ArrayList<>();
        for (final String key : walletKeys()) {
            all.add(key);
            if ("hash".equals(REDIS_TEMPLATE.type(key).code())) {
                for (final Map.Entry<Object, Object> e : REDIS_TEMPLATE.opsForHash().entries(key).entrySet()) {
                    all.add(String.valueOf(e.getKey()));
                    all.add(String.valueOf(e.getValue()));
                }
            } else {
                all.add(REDIS_TEMPLATE.opsForValue().get(key));
            }
        }
        return all;
    }

    @Test
    void everyKey_hasATtl_noLongerThanTheTransaction() {
        final Verified v = verified();

        final Set<String> keys = walletKeys();
        assertThat(keys).hasSize(5) // the hash + req (2) + resp + code
                .contains("helix:wallet:tx:" + v.tx().transactionId(),
                        "helix:wallet:code:" + SecretHash.of(v.code()),
                        "helix:wallet:resp:" + SecretHash.of(v.tx().responseId()),
                        "helix:wallet:req:" + SecretHash.of(v.tx().sameDeviceRequestId()),
                        "helix:wallet:req:" + SecretHash.of(v.tx().crossDeviceRequestId()));
        for (final String key : keys) {
            final Long ttlMillis = REDIS_TEMPLATE.getExpire(key, java.util.concurrent.TimeUnit.MILLISECONDS);
            assertThat(ttlMillis).as(key).isPositive().isLessThanOrEqualTo(TTL.toMillis());
        }
    }

    @Test
    void aKeyDump_revealsNoBearerSecret_noPrivateKey_andNoIdentity() {
        final Verified v = verified();
        final WalletTransaction tx = v.tx();
        final WalletTransaction fetchedOnly = requestFetched(); // still holds its private key

        final List<String> dump = dump();

        final String privateD = "Hndv7ZZjs_ke8o9zXYo3iq-Yr8SewI5vrqd0pAvEPqg";
        for (final String entry : dump) {
            assertThat(entry).isNotNull()
                    .doesNotContain(v.code(), tx.sameDeviceRequestId(), tx.crossDeviceRequestId(), tx.responseId(),
                            fetchedOnly.sameDeviceRequestId(), fetchedOnly.crossDeviceRequestId(),
                            fetchedOnly.responseId(), privateD, "Erika");
        }
        // ...and the store still reads everything back.
        final WalletTransaction read = store.byTransactionId(fetchedOnly.transactionId()).orElseThrow();
        assertThat(read.encryptionJwkJson()).isEqualTo(JWK);
        assertThat(read.crossDeviceRequestId()).isEqualTo(fetchedOnly.crossDeviceRequestId());
        assertThat(read.responseId()).isEqualTo(fetchedOnly.responseId());
    }

    @Test
    void withoutDbEncryption_createIsRefusedOutsideDev_andAllowedInDev() {
        flushAll();
        final AttributeEncryption none = new AttributeEncryption(null);
        final WalletTransactionStore production =
                new RedisWalletTransactionStore(FACTORY, none, DeploymentProfile.production(), clock);
        final WalletTransaction tx = newTransaction();

        assertThatThrownBy(() -> production.create(tx)).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("DB_ENCRYPTION");
        assertThat(walletKeys()).isEmpty();

        final WalletTransactionStore dev =
                new RedisWalletTransactionStore(FACTORY, none, DeploymentProfile.development(), clock);
        dev.create(tx);
        assertThat(dev.byTransactionId(tx.transactionId()).orElseThrow().encryptionJwkJson()).isEqualTo(JWK);
    }

    @Test
    void expired_isAbsentEvenWhileRedisStillHoldsTheKey() {
        final WalletTransaction tx = created();

        clock.advance(TTL);

        assertThat(REDIS_TEMPLATE.hasKey("helix:wallet:tx:" + tx.transactionId())).isTrue();
        assertThat(store.byTransactionId(tx.transactionId())).isEmpty();
        assertThat(store.claimRequest(tx.crossDeviceRequestId())).isEmpty();
    }
}
