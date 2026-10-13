/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import io.helixiam.authorization.security.FilteredJdkRedisSerializer;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
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
 *   <li>The session mappers of both Redis repositories return no session when any attribute is unreadable, and the
 *       session is deleted: the default repository ({@link RedisSessionRepository}) deletes a session its mapper
 *       refuses; the indexed one ({@code repository-type=indexed}) does not, so the mapper deletes its keys itself (the
 *       session hash and its expiry key), which also keeps the WARN to one line per refused session.</li>
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
        // RedisSessionRepository.findById deletes a session its mapper refuses.
        return repository -> repository.setRedisSessionMapper(mapper(sessionId -> { }));
    }

    @Bean
    public SessionRepositoryCustomizer<RedisIndexedSessionRepository> dropUnreadableIndexedSessions(
            @Value("${spring.session.data.redis.namespace:spring:session}") final String namespace) {
        // RedisIndexedSessionRepository only returns no session (its deleteById would map the session again), so the
        // refused session's keys are deleted here, with the repository's own Redis operations.
        return repository -> repository.setRedisSessionMapper(mapper(sessionId -> {
            repository.getSessionRedisOperations().delete(namespace + ":sessions:" + sessionId);
            repository.getSessionRedisOperations().delete(namespace + ":sessions:expires:" + sessionId);
        }));
    }

    /** Spring Session's mapper, except that a session with an unreadable value maps to none (after {@code drop}). */
    static BiFunction<String, Map<String, Object>, MapSession> mapper(final java.util.function.Consumer<String> drop) {
        final RedisSessionMapper standard = new RedisSessionMapper();
        return (sessionId, entries) -> {
            for (final Map.Entry<String, Object> entry : entries.entrySet()) {
                if (entry.getValue() == FilteredJdkRedisSerializer.UNREADABLE) {
                    final String key = entry.getKey().startsWith(ATTRIBUTE_PREFIX)
                            ? entry.getKey().substring(ATTRIBUTE_PREFIX.length()) : entry.getKey();
                    LOG.warn("HTTP session dropped: its attribute {} could not be read or is refused by the session"
                            + " store's allowlist; the user has to sign in again", LogSafe.sanitize(key));
                    drop.accept(sessionId);
                    return null;
                }
            }
            return standard.apply(sessionId, entries);
        };
    }
}
