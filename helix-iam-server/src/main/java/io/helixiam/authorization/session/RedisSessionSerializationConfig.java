/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import io.helixiam.authorization.security.FilteredJdkRedisSerializer;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.session.MapSession;
import org.springframework.session.config.SessionRepositoryCustomizer;
import org.springframework.session.data.redis.RedisIndexedSessionRepository;
import org.springframework.session.data.redis.RedisSessionMapper;
import org.springframework.session.data.redis.RedisSessionRepository;

import java.util.Map;
import java.util.function.BiFunction;

/**
 * The Redis HTTP-session store (Spring Session Data Redis, the default {@code helix.iam.session-store=redis}) reads
 * session attributes through the same JEP-290 allowlist as the queue store ({@code SessionBlobs}), and drops a session
 * it cannot read as a whole, as the queue store does: the user signs in again instead of the request failing.
 *
 * <ul>
 *   <li>{@code springSessionDefaultRedisSerializer}, the bean Spring Session uses for every session value, is a
 *       {@link FilteredJdkRedisSerializer}: the same bytes as before, read through the allowlist; a refused or
 *       unreadable attribute reads as {@link FilteredJdkRedisSerializer#UNREADABLE}.</li>
 *   <li>The session mappers of both Redis repositories return no session when any attribute is unreadable; the
 *       repository then deletes it.</li>
 * </ul>
 * With the queue store these beans are unused (Spring Session's Redis configuration backs off).
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(RedisSessionRepository.class)
public class RedisSessionSerializationConfig {

    private static final Logger LOG = LogManager.getLogger(RedisSessionSerializationConfig.class);
    private static final String ATTRIBUTE_PREFIX = "sessionAttr:";

    @Bean("springSessionDefaultRedisSerializer")
    public RedisSerializer<Object> springSessionDefaultRedisSerializer() {
        return FilteredJdkRedisSerializer.forSessions();
    }

    @Bean
    public SessionRepositoryCustomizer<RedisSessionRepository> dropUnreadableSessions() {
        return repository -> repository.setRedisSessionMapper(mapper());
    }

    @Bean
    public SessionRepositoryCustomizer<RedisIndexedSessionRepository> dropUnreadableIndexedSessions() {
        return repository -> repository.setRedisSessionMapper(mapper());
    }

    /** Spring Session's mapper, except that a session with an unreadable value maps to none. */
    static BiFunction<String, Map<String, Object>, MapSession> mapper() {
        final RedisSessionMapper standard = new RedisSessionMapper();
        return (sessionId, entries) -> {
            for (final Map.Entry<String, Object> entry : entries.entrySet()) {
                if (entry.getValue() == FilteredJdkRedisSerializer.UNREADABLE) {
                    final String key = entry.getKey().startsWith(ATTRIBUTE_PREFIX)
                            ? entry.getKey().substring(ATTRIBUTE_PREFIX.length()) : entry.getKey();
                    LOG.warn("HTTP session dropped: its attribute {} could not be read or is refused by the session"
                            + " store's allowlist; the user has to sign in again", LogSafe.sanitize(key));
                    return null;
                }
            }
            return standard.apply(sessionId, entries);
        };
    }
}
