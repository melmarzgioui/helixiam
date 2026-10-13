/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import org.springframework.core.ConfigurableObjectInputStream;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.SerializationException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.io.ObjectStreamField;
import java.util.Arrays;
import java.util.Comparator;

/**
 * Spring Boot 4 upgrade: reads OAuth2 authorizations that HelixIAM 1.0 (Spring Authorization Server 1.5) wrote with
 * Java serialization.
 *
 * <p>Spring Authorization Server 1.x gave most of its serializable classes one shared {@code serialVersionUID},
 * {@value #SAS_1_SERIAL_VERSION_UID} ({@code SpringAuthorizationServerVersion.SERIAL_VERSION_UID}). Since the
 * authorization server became part of Spring Security 7 each class has its own value, so a stored
 * {@code OAuth2Authorization} (authorization codes, refresh tokens, consents in flight, the queue and Redis token
 * stores) fails with {@link java.io.InvalidClassException} and would be dropped: every refresh token issued before the
 * upgrade would stop working. The serialized form of these classes did not change (same fields, same types).
 *
 * <p>The compatibility is deliberately narrow: a stream class descriptor is replaced by the local one only when
 * <ul>
 *   <li>the class is in {@code org.springframework.security.oauth2.server.authorization},</li>
 *   <li>the stream carries exactly the 1.x UID {@value #SAS_1_SERIAL_VERSION_UID}, and</li>
 *   <li>the stream's serializable fields equal the local class's (name and type).</li>
 * </ul>
 * Anything else is left to the JDK's own check. The class is still resolved through {@code resolveClass}, so the
 * callers' {@link java.io.ObjectInputFilter} allowlists apply unchanged.
 */
public final class LegacyAuthorizationServerSerialization {

    /** {@code SpringAuthorizationServerVersion.SERIAL_VERSION_UID} of Spring Authorization Server 1.x. */
    static final long SAS_1_SERIAL_VERSION_UID = 46675322L;

    private static final String SAS_PACKAGE = "org.springframework.security.oauth2.server.authorization.";

    private LegacyAuthorizationServerSerialization() {
    }

    /** An {@link ObjectInputStream} that accepts Spring Authorization Server 1.x class descriptors (see above). */
    public static ObjectInputStream objectInputStream(final InputStream in) throws IOException {
        return new ObjectInputStream(in) {
            @Override
            protected ObjectStreamClass readClassDescriptor() throws IOException, ClassNotFoundException {
                return compatible(super.readClassDescriptor());
            }
        };
    }

    /**
     * A drop-in for {@link JdkSerializationRedisSerializer}: writes the same bytes, and reads them back accepting
     * Spring Authorization Server 1.x class descriptors.
     */
    public static RedisSerializer<Object> redisSerializer() {
        return new UpgradeCompatibleRedisSerializer();
    }

    /** The local descriptor for a Spring Authorization Server 1.x descriptor with identical fields, else {@code stream}. */
    static ObjectStreamClass compatible(final ObjectStreamClass stream) {
        if (stream.getSerialVersionUID() != SAS_1_SERIAL_VERSION_UID || !stream.getName().startsWith(SAS_PACKAGE)) {
            return stream;
        }
        final Class<?> type;
        try {
            type = Class.forName(stream.getName(), false, LegacyAuthorizationServerSerialization.class.getClassLoader());
        } catch (final ClassNotFoundException | LinkageError e) {
            return stream;
        }
        final ObjectStreamClass local = ObjectStreamClass.lookup(type);
        if (local == null || local.getSerialVersionUID() == stream.getSerialVersionUID()
                || !sameFields(stream.getFields(), local.getFields())) {
            return stream;
        }
        return local;
    }

    private static boolean sameFields(final ObjectStreamField[] stream, final ObjectStreamField[] local) {
        if (stream.length != local.length) {
            return false;
        }
        final Comparator<ObjectStreamField> byName = Comparator.comparing(ObjectStreamField::getName);
        final ObjectStreamField[] a = stream.clone();
        final ObjectStreamField[] b = local.clone();
        Arrays.sort(a, byName);
        Arrays.sort(b, byName);
        for (int i = 0; i < a.length; i++) {
            if (!a[i].getName().equals(b[i].getName()) || a[i].getTypeCode() != b[i].getTypeCode()
                    || !String.valueOf(a[i].getTypeString()).equals(String.valueOf(b[i].getTypeString()))) {
                return false;
            }
        }
        return true;
    }

    private static final class UpgradeCompatibleRedisSerializer implements RedisSerializer<Object> {

        private final JdkSerializationRedisSerializer writer = new JdkSerializationRedisSerializer();

        @Override
        public byte[] serialize(final Object value) {
            return writer.serialize(value);
        }

        @Override
        public Object deserialize(final byte[] bytes) {
            if (bytes == null || bytes.length == 0) {
                return null;
            }
            try (ObjectInputStream in = new ConfigurableObjectInputStream(new ByteArrayInputStream(bytes),
                    LegacyAuthorizationServerSerialization.class.getClassLoader()) {
                @Override
                protected ObjectStreamClass readClassDescriptor() throws IOException, ClassNotFoundException {
                    return compatible(super.readClassDescriptor());
                }
            }) {
                return in.readObject();
            } catch (final Exception e) {
                throw new SerializationException("Cannot deserialize", e);
            }
        }
    }
}
