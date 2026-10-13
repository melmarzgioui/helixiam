/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;

import javax.management.BadAttributeValueExpException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The Redis HTTP-session store (the default) applies the same JEP-290 allowlist as the queue store: a session whose
 * attributes hold a class outside it (a deserialization gadget planted in Redis, or a session written by a version
 * that has classes this one does not) is dropped as a whole and deleted. The user is signed out instead of the request
 * failing, and the gadget is never constructed.
 */
class RedisSessionAllowlistE2eTest extends AbstractE2eTest {

    private static final JdkSerializationRedisSerializer JDK = new JdkSerializationRedisSerializer();

    @Test
    void aSessionHoldingAClassOutsideTheAllowlist_isDroppedAndDeleted_notA500() {
        final String gadget = plantSession(new BadAttributeValueExpException("planted"));
        final String control = plantSession("an ordinary value");

        final E2eHttp.Response dropped = newBrowser().get("/realms/" + MASTER + "/account",
                "Cookie", "SESSION=" + cookie(gadget));
        final E2eHttp.Response kept = newBrowser().get("/realms/" + MASTER + "/account",
                "Cookie", "SESSION=" + cookie(control));

        assertThat(dropped.status()).as(dropped.toString()).isEqualTo(302);
        assertThat(redis().hasKey(key(gadget))).as("the refused session is deleted").isFalse();
        assertThat(kept.status()).isEqualTo(302); // not signed in either, but its session is used and kept
        assertThat(redis().hasKey(key(control))).as("a readable session is kept").isTrue();
    }

    /** A session the way Spring Session's RedisSessionRepository stores it, with one attribute. */
    private String plantSession(final Object attribute) {
        final String id = UUID.randomUUID().toString();
        final byte[] key = key(id).getBytes(StandardCharsets.UTF_8);
        final long now = System.currentTimeMillis();
        try (var connection = context.getBean(RedisConnectionFactory.class).getConnection()) {
            connection.hashCommands().hSet(key, field("creationTime"), JDK.serialize(now));
            connection.hashCommands().hSet(key, field("lastAccessedTime"), JDK.serialize(now));
            connection.hashCommands().hSet(key, field("maxInactiveInterval"), JDK.serialize(1800));
            connection.hashCommands().hSet(key, field("sessionAttr:planted"), JDK.serialize(attribute));
        }
        assertThat(redis().hasKey(key(id))).isTrue();
        return id;
    }

    private StringRedisTemplate redis() {
        return new StringRedisTemplate(context.getBean(RedisConnectionFactory.class));
    }

    private static byte[] field(final String name) {
        return name.getBytes(StandardCharsets.UTF_8);
    }

    private static String key(final String id) {
        return "spring:session:sessions:" + id;
    }

    private static String cookie(final String id) {
        return Base64.getEncoder().encodeToString(id.getBytes(StandardCharsets.UTF_8));
    }
}
