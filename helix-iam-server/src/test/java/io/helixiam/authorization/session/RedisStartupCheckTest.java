/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import org.junit.jupiter.api.Test;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** An unreachable Redis session store fails startup with an actionable message. */
class RedisStartupCheckTest {

    @Test
    void unreachableRedis_failsStartupWithAClearMessage() {
        final RedisConnectionFactory factory = mock(RedisConnectionFactory.class);
        when(factory.getConnection()).thenThrow(new RedisConnectionFailureException("Connection refused"));

        assertThatThrownBy(() -> new RedisStartupCheck(factory, true, "localhost", 6379).afterSingletonsInstantiated())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("cannot reach Redis at localhost:6379")
                .hasMessageContaining("HELIX_SESSION_STORE=queue");
    }

    @Test
    void reachableRedis_orDisabledCheck_passes() {
        final RedisConnectionFactory factory = mock(RedisConnectionFactory.class);
        when(factory.getConnection()).thenReturn(mock(RedisConnection.class));
        assertThatCode(() -> new RedisStartupCheck(factory, true, "localhost", 6379).afterSingletonsInstantiated())
                .doesNotThrowAnyException();

        final RedisConnectionFactory broken = mock(RedisConnectionFactory.class);
        when(broken.getConnection()).thenThrow(new RedisConnectionFailureException("down"));
        assertThatCode(() -> new RedisStartupCheck(broken, false, "localhost", 6379).afterSingletonsInstantiated())
                .doesNotThrowAnyException();
    }
}
