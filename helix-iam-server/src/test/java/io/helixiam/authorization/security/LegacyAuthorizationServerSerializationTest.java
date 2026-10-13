/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.Externalizable;
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.Serializable;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Guards {@link LegacyAuthorizationServerSerialization}: the classes it accepts with Spring Authorization Server 1.x's
 * shared {@code serialVersionUID}, and that it accepts a stream descriptor only when its flags and fields are what the
 * local class reads.
 */
class LegacyAuthorizationServerSerializationTest {

    private static final long SAS_1_UID = 46675322L;

    @Test
    void theAcceptedClasses_areExactlyThe1_5ClassesWhoseSerializedFormIsUnchanged() throws IOException {
        final Map<String, String> recorded = recordedFingerprints();
        assertThat(recorded).hasSize(22);

        assertThat(LegacyAuthorizationServerSerialization.acceptedClasses())
                .containsExactlyInAnyOrderElementsOf(recorded.keySet());
    }

    @Test
    void everyAcceptedClass_stillHasThe1_5SerializedForm() throws Exception {
        // A Spring Security patch that changes one of these (fields, writeObject, Externalizable, enum) fails here, and
        // the class has to leave the accepted set rather than be read with the wrong layout.
        for (final Map.Entry<String, String> entry : recordedFingerprints().entrySet()) {
            final Class<?> local = Class.forName(entry.getKey(), false, getClass().getClassLoader());
            assertThat(fingerprint(local)).as(entry.getKey()).isEqualTo(entry.getValue());
            assertThat(ObjectStreamClass.lookup(local).getSerialVersionUID()).as(entry.getKey()).isNotEqualTo(SAS_1_UID);
        }
    }

    @Test
    void aDescriptorWhoseFlagsDiffer_isRefused_evenForAnAcceptedClassWithTheSameFields() throws Exception {
        final byte[] blob = Base64.getDecoder().decode(resource("/upgrade/boot3/authorization.b64").trim());
        assertThat(read(blob)).isNotNull(); // as written by 1.0: accepted

        final String token = "org.springframework.security.oauth2.server.authorization.OAuth2Authorization$Token";
        final int flags = flagsOffset(blob, token);
        assertThat(blob[flags]).isEqualTo((byte) 0x02); // SC_SERIALIZABLE
        for (final byte forged : new byte[] {0x03 /* + SC_WRITE_METHOD */, 0x04 /* SC_EXTERNALIZABLE */,
                0x0c /* + SC_BLOCK_DATA */, 0x12 /* + SC_ENUM */}) {
            final byte[] tampered = blob.clone();
            tampered[flags] = forged;
            assertThatThrownBy(() -> read(tampered)).as("flags 0x%02x", forged)
                    .isInstanceOf(InvalidClassException.class).hasMessageContaining("OAuth2Authorization$Token");
        }
    }

    @Test
    void aClassOutsideTheAcceptedSet_isLeftToTheJdk_evenWithTheLegacyUidAndUnchangedFields() throws Exception {
        // The 1.x UID on a class that is not in the set (here: a test class) is never rewritten.
        final byte[] blob = serialize(new NotAccepted("x"));
        final int uid = flagsOffset(blob, NotAccepted.class.getName()) - 8;
        final byte[] forged = blob.clone();
        for (int i = 0; i < 8; i++) {
            forged[uid + i] = (byte) (SAS_1_UID >>> (56 - 8 * i));
        }
        assertThatThrownBy(() -> read(forged)).isInstanceOf(InvalidClassException.class)
                .hasMessageContaining("local class incompatible");
    }

    static final class NotAccepted implements Serializable {
        private static final long serialVersionUID = 1L;
        private final String value;

        NotAccepted(final String value) {
            this.value = value;
        }
    }

    private static Object read(final byte[] blob) throws Exception {
        try (ObjectInputStream in = LegacyAuthorizationServerSerialization.objectInputStream(blob)) {
            return in.readObject();
        }
    }

    private static byte[] serialize(final Object value) throws IOException {
        final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(value);
        }
        return bytes.toByteArray();
    }

    /** Offset of the flags byte of the (first) class descriptor for {@code className}: after its UTF name and UID. */
    private static int flagsOffset(final byte[] blob, final String className) {
        final byte[] name = className.getBytes(StandardCharsets.UTF_8);
        outer:
        for (int i = 3; i + name.length + 8 < blob.length; i++) {
            if (blob[i - 3] != 0x72 /* TC_CLASSDESC */ || ((blob[i - 2] & 0xff) << 8 | (blob[i - 1] & 0xff)) != name.length) {
                continue;
            }
            for (int j = 0; j < name.length; j++) {
                if (blob[i + j] != name[j]) {
                    continue outer;
                }
            }
            return i + name.length + 8;
        }
        throw new AssertionError(className + " not in the blob");
    }

    /** Same notation as the resource: SC_* flags as the JDK writes them, and the serialized fields sorted by name. */
    static String fingerprint(final Class<?> type) {
        int flags = 0;
        if (Externalizable.class.isAssignableFrom(type)) {
            flags |= 0x04;
        } else if (Serializable.class.isAssignableFrom(type)) {
            flags |= 0x02;
        }
        try {
            final Method writeObject = type.getDeclaredMethod("writeObject", ObjectOutputStream.class);
            if (Modifier.isPrivate(writeObject.getModifiers()) && !Modifier.isStatic(writeObject.getModifiers())
                    && writeObject.getReturnType() == void.class) {
                flags |= 0x01;
            }
        } catch (final NoSuchMethodException none) {
            // no writeObject
        }
        if (type.isEnum()) {
            flags |= 0x10;
        }
        final List<String> fields = new ArrayList<>();
        for (final var field : ObjectStreamClass.lookupAny(type).getFields()) {
            fields.add(field.getName() + ":" + (field.getTypeString() == null
                    ? String.valueOf(field.getTypeCode()) : field.getTypeString()));
        }
        Collections.sort(fields);
        return "flags=" + flags + " " + fields;
    }

    private static Map<String, String> recordedFingerprints() throws IOException {
        final Map<String, String> out = new TreeMap<>();
        for (final String line : resource("/upgrade/sas-1.5-serial-fingerprints.txt").split("\n")) {
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }
            final int bar = line.indexOf(" | ");
            out.put(line.substring(0, bar), line.substring(bar + 3));
        }
        return out;
    }

    private static String resource(final String path) throws IOException {
        try (InputStream in = LegacyAuthorizationServerSerializationTest.class.getResourceAsStream(path)) {
            assertThat(in).as(path).isNotNull();
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
