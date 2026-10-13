/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.ObjectStreamField;
import java.io.Serializable;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Set;

/**
 * Spring Boot 4 upgrade: reads OAuth2 authorizations that HelixIAM 1.0 (Spring Authorization Server 1.5) wrote with
 * Java serialization.
 *
 * <p>Spring Authorization Server 1.x gave most of its serializable classes one shared {@code serialVersionUID},
 * {@value #SAS_1_SERIAL_VERSION_UID} ({@code SpringAuthorizationServerVersion.SERIAL_VERSION_UID}). Since the
 * authorization server became part of Spring Security 7 each class has its own value, so a stored
 * {@code OAuth2Authorization} (authorization codes, refresh tokens, consents in flight, the queue and Redis token
 * stores) fails with {@link java.io.InvalidClassException} and would be dropped: every refresh token issued before the
 * upgrade would stop working.
 *
 * <p>The compatibility is deliberately narrow. A stream class descriptor is replaced by the local one only when
 * <ul>
 *   <li>the class is one of {@link #acceptedClasses()}: the 22 classes 1.5 serialized with that UID whose serialized
 *       form is unchanged in Spring Security 7 (compared field by field and flag by flag, 1.5.8 against 7.1.1);</li>
 *   <li>the stream carries exactly the 1.x UID {@value #SAS_1_SERIAL_VERSION_UID};</li>
 *   <li>the stream's descriptor flags ({@code SC_WRITE_METHOD}, {@code SC_SERIALIZABLE}, {@code SC_EXTERNALIZABLE},
 *       {@code SC_BLOCK_DATA}, {@code SC_ENUM}) are those the local class is written with. The JDK reads the instance
 *       data with the descriptor returned here, so a mismatch would be misread. The JDK keeps a descriptor's flags
 *       private, so they are read from the raw descriptor bytes; when the raw name and UID found there are not the
 *       parsed descriptor's, nothing is accepted (fail closed);</li>
 *   <li>the stream's serializable fields equal the local class's (name and type).</li>
 * </ul>
 * Anything else is left to the JDK's own check (an {@link java.io.InvalidClassException}). Classes are still resolved
 * through {@code resolveClass}, so the callers' {@link java.io.ObjectInputFilter} allowlists apply unchanged.
 */
public final class LegacyAuthorizationServerSerialization {

    /** {@code SpringAuthorizationServerVersion.SERIAL_VERSION_UID} of Spring Authorization Server 1.x. */
    static final long SAS_1_SERIAL_VERSION_UID = 46675322L;

    private static final String SAS = "org.springframework.security.oauth2.server.authorization.";

    /**
     * The 1.5 classes with the shared UID whose serialized form Spring Security 7 kept. Pinned by
     * {@code LegacyAuthorizationServerSerializationTest} against fingerprints recorded from the 1.5.8 jar.
     */
    private static final Set<String> ACCEPTED = Set.of(
            SAS + "AbstractOAuth2AuthorizationServerMetadata",
            SAS + "OAuth2Authorization",
            SAS + "OAuth2Authorization$Token",
            SAS + "OAuth2AuthorizationConsent",
            SAS + "OAuth2TokenIntrospection",
            SAS + "OAuth2TokenType",
            SAS + "authentication.AbstractOAuth2AuthorizationCodeRequestAuthenticationToken",
            SAS + "authentication.OAuth2AccessTokenAuthenticationToken",
            SAS + "authentication.OAuth2AuthorizationConsentAuthenticationToken",
            SAS + "authentication.OAuth2AuthorizationGrantAuthenticationToken",
            SAS + "authentication.OAuth2ClientAuthenticationToken",
            SAS + "authentication.OAuth2DeviceAuthorizationConsentAuthenticationToken",
            SAS + "authentication.OAuth2DeviceAuthorizationRequestAuthenticationToken",
            SAS + "authentication.OAuth2DeviceVerificationAuthenticationToken",
            SAS + "authentication.OAuth2TokenIntrospectionAuthenticationToken",
            SAS + "authentication.OAuth2TokenRevocationAuthenticationToken",
            SAS + "client.RegisteredClient",
            SAS + "oidc.authentication.OidcClientRegistrationAuthenticationToken",
            SAS + "oidc.authentication.OidcLogoutAuthenticationToken",
            SAS + "oidc.authentication.OidcUserInfoAuthenticationToken",
            SAS + "settings.AbstractSettings",
            SAS + "settings.OAuth2TokenFormat");

    private static final int SC_WRITE_METHOD = 0x01;
    private static final int SC_SERIALIZABLE = 0x02;
    private static final int SC_EXTERNALIZABLE = 0x04;
    private static final int SC_BLOCK_DATA = 0x08;
    private static final int SC_ENUM = 0x10;

    private LegacyAuthorizationServerSerialization() {
    }

    /** The classes whose 1.x descriptors are accepted. */
    public static Set<String> acceptedClasses() {
        return ACCEPTED;
    }

    /** An {@link ObjectInputStream} over {@code data} that accepts Spring Authorization Server 1.x descriptors. */
    public static ObjectInputStream objectInputStream(final byte[] data) throws IOException {
        return new CompatibleObjectInputStream(new PositionedInput(data), data);
    }

    private static final class PositionedInput extends ByteArrayInputStream {
        PositionedInput(final byte[] data) {
            super(data);
        }

        int position() {
            return pos;
        }
    }

    private static final class CompatibleObjectInputStream extends ObjectInputStream {
        private final PositionedInput input;
        private final byte[] data;

        CompatibleObjectInputStream(final PositionedInput input, final byte[] data) throws IOException {
            super(input);
            this.input = input;
            this.data = data;
        }

        @Override
        protected ObjectStreamClass readClassDescriptor() throws IOException, ClassNotFoundException {
            // A class descriptor is read outside block-data mode, straight from the underlying stream (its TC_CLASSDESC
            // byte already consumed), so its raw bytes start here. rawFlags verifies that before trusting it.
            final int start = input.position();
            final ObjectStreamClass stream = super.readClassDescriptor();
            if (stream.getSerialVersionUID() != SAS_1_SERIAL_VERSION_UID || !ACCEPTED.contains(stream.getName())) {
                return stream;
            }
            final int flags = rawFlags(data, start, stream);
            return flags < 0 ? stream : compatible(stream, flags);
        }
    }

    /**
     * The descriptor flags at {@code start} (modified-UTF-8 name with its length, 8-byte UID, flags byte), or -1 when
     * the raw name or UID found there is not the parsed descriptor's.
     */
    static int rawFlags(final byte[] data, final int start, final ObjectStreamClass stream) {
        final byte[] name = modifiedUtf8(stream.getName());
        final int flagsAt = start + 2 + name.length + 8;
        if (start < 0 || flagsAt >= data.length
                || ((data[start] & 0xff) << 8 | (data[start + 1] & 0xff)) != name.length
                || !Arrays.equals(data, start + 2, start + 2 + name.length, name, 0, name.length)) {
            return -1;
        }
        long uid = 0;
        for (int i = 0; i < 8; i++) {
            uid = (uid << 8) | (data[start + 2 + name.length + i] & 0xff);
        }
        return uid == stream.getSerialVersionUID() ? data[flagsAt] & 0xff : -1;
    }

    /** The local descriptor for an accepted 1.x descriptor with the local flags and fields, else {@code stream}. */
    static ObjectStreamClass compatible(final ObjectStreamClass stream, final int streamFlags) {
        final Class<?> type;
        try {
            type = Class.forName(stream.getName(), false, LegacyAuthorizationServerSerialization.class.getClassLoader());
        } catch (final ClassNotFoundException | LinkageError e) {
            return stream;
        }
        final ObjectStreamClass local = ObjectStreamClass.lookup(type);
        if (local == null || local.getSerialVersionUID() == stream.getSerialVersionUID()
                || streamFlags != localFlags(type)
                || !sameFields(stream.getFields(), local.getFields())) {
            return stream;
        }
        return local;
    }

    /** The flags {@link ObjectOutputStream} (protocol 2, the default) writes for {@code type}'s descriptor. */
    static int localFlags(final Class<?> type) {
        int flags = 0;
        if (Externalizable.class.isAssignableFrom(type)) {
            flags |= SC_EXTERNALIZABLE | SC_BLOCK_DATA;
        } else if (Serializable.class.isAssignableFrom(type)) {
            flags |= SC_SERIALIZABLE;
        }
        try {
            final Method writeObject = type.getDeclaredMethod("writeObject", ObjectOutputStream.class);
            if (Modifier.isPrivate(writeObject.getModifiers()) && !Modifier.isStatic(writeObject.getModifiers())
                    && writeObject.getReturnType() == void.class) {
                flags |= SC_WRITE_METHOD;
            }
        } catch (final NoSuchMethodException none) {
            // no custom writeObject
        }
        if (type.isEnum()) {
            flags |= SC_ENUM;
        }
        return flags;
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

    /** {@link java.io.DataOutput#writeUTF}'s encoding, without the length prefix. */
    private static byte[] modifiedUtf8(final String value) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i < value.length(); i++) {
            final char c = value.charAt(i);
            if (c >= 0x0001 && c <= 0x007F) {
                out.write(c);
            } else if (c > 0x07FF) {
                out.write(0xE0 | ((c >> 12) & 0x0F));
                out.write(0x80 | ((c >> 6) & 0x3F));
                out.write(0x80 | (c & 0x3F));
            } else {
                out.write(0xC0 | ((c >> 6) & 0x1F));
                out.write(0x80 | (c & 0x3F));
            }
        }
        return out.toByteArray();
    }
}
