/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import io.helixiam.authorization.session.RedisSessionSerializationConfig;
import io.helixiam.authorization.session.SsoSessionStoreConfig;
import io.helixiam.testsupport.LogCapture;
import io.helixiam.upgrade.PersistedStateFixtures;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.session.MapSession;
import org.springframework.session.data.redis.RedisSessionRepository;

import javax.management.BadAttributeValueExpException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiFunction;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Pre-existing gap: the Redis token store, the Redis SSO-session reader and Spring Session's Redis store deserialized
 * with plain {@code JdkSerializationRedisSerializer}, without the JEP-290 allowlist the queue (PostgreSQL) blobs apply.
 * They now use the same allowlists, and an entry that is refused or unreadable is treated as absent, not an error.
 */
class FilteredJdkRedisSerializerTest {

    private static final byte[] GADGET = new JdkSerializationRedisSerializer()
            .serialize(new BadAttributeValueExpException("secret-gadget-content"));

    @Test
    void theTokenStoreSerializer_refusesAGadget_asAbsent_andLogsOnlyTheClass() {
        final RedisSerializer<Object> serializer = FilteredJdkRedisSerializer.forAuthorizations();
        try (LogCapture log = LogCapture.of(FilteredJdkRedisSerializer.class)) {
            assertThat(serializer.deserialize(GADGET)).isNull();
            assertThat(log.text()).contains("javax.management.BadAttributeValueExpException")
                    .doesNotContain("secret-gadget-content");
        }
        assertThat(serializer.deserialize("not java serialization".getBytes(StandardCharsets.UTF_8))).isNull();
        assertThat(serializer.deserialize(null)).isNull();
    }

    @Test
    void theTokenStoreSerializer_readsWhat1_0AndThisLineWrite_andWritesTheSameBytesAsBefore() throws IOException {
        final RedisSerializer<Object> serializer = FilteredJdkRedisSerializer.forAuthorizations();
        final OAuth2Authorization stored = (OAuth2Authorization) serializer.deserialize(
                Base64.getDecoder().decode(resource("/upgrade/boot3/authorization.b64")));
        assertThat(stored.getRefreshToken().getToken().getTokenValue()).isEqualTo("refresh-1");

        final OAuth2Authorization current = PersistedStateFixtures.authorization();
        final byte[] written = serializer.serialize(current);
        assertThat(written).isEqualTo(new JdkSerializationRedisSerializer().serialize(current));
        assertThat(((OAuth2Authorization) serializer.deserialize(written)).getId()).isEqualTo("auth-1");
    }

    @Test
    void theTokenAndSsoStoreTemplates_useTheFilteredSerializer() {
        final RedisConnectionFactory factory = mock(RedisConnectionFactory.class);
        for (final RedisTemplate<String, Object> template : new RedisTemplate[] {
                PersistenceConfig.authorizationTemplate(factory), SsoSessionStoreConfig.authorizationTemplate(factory)}) {
            assertThat(template.getValueSerializer()).isInstanceOf(FilteredJdkRedisSerializer.class);
            assertThat(template.getValueSerializer().deserialize(GADGET)).isNull();
        }
    }

    @Test
    void theSessionSerializer_marksARefusedAttribute_andTheSessionIsDroppedWhole() {
        final RedisSerializer<Object> serializer = new RedisSessionSerializationConfig().springSessionDefaultRedisSerializer();
        assertThat(serializer).isInstanceOf(FilteredJdkRedisSerializer.class);
        final Object refused = serializer.deserialize(GADGET);
        assertThat(refused).isSameAs(FilteredJdkRedisSerializer.UNREADABLE);
        // An ordinary session attribute (a sign-in's saved request, CSRF token, …) still reads.
        assertThat(serializer.deserialize(serializer.serialize(1_790_000_000L))).isEqualTo(1_790_000_000L);

        final RedisSessionRepository repository = mock(RedisSessionRepository.class);
        final org.mockito.ArgumentCaptor<BiFunction<String, Map<String, Object>, MapSession>> mapper =
                org.mockito.ArgumentCaptor.forClass(BiFunction.class);
        new RedisSessionSerializationConfig().dropUnreadableSessions().customize(repository);
        org.mockito.Mockito.verify(repository).setRedisSessionMapper(mapper.capture());

        final Map<String, Object> entries = new HashMap<>();
        entries.put("creationTime", 1_790_000_000_000L);
        entries.put("lastAccessedTime", 1_790_000_000_000L);
        entries.put("maxInactiveInterval", 1800);
        entries.put("sessionAttr:HELIX_SID", "sid-1");
        assertThat((Object) mapper.getValue().apply("s-1", entries).getAttribute("HELIX_SID")).isEqualTo("sid-1");
        entries.put("sessionAttr:SPRING_SECURITY_CONTEXT", FilteredJdkRedisSerializer.UNREADABLE);
        try (LogCapture log = LogCapture.of(RedisSessionSerializationConfig.class)) {
            assertThat(mapper.getValue().apply("s-1", entries)).as("the whole session is dropped").isNull();
            assertThat(log.text()).contains("SPRING_SECURITY_CONTEXT");
        }
    }

    private static String resource(final String path) throws IOException {
        try (InputStream in = FilteredJdkRedisSerializerTest.class.getResourceAsStream(path)) {
            return new String(in.readAllBytes(), StandardCharsets.US_ASCII).trim();
        }
    }
}
