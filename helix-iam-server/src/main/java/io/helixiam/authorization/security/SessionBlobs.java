/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Base64;
import java.util.Map;

/**
 * Helix IAM (Q3): (de)serialization of an HTTP session's attribute map to/from the opaque base64 blob the
 * queue-backed session store persists in the subscriber.
 *
 * <p>Security: a strict JEP-290 allowlist constrains deserialization to the types a login session legitimately
 * holds — Spring Security (SecurityContext, saved request, CSRF), Spring Web/Session, our own principal/claim
 * types, and JDK value types — and rejects everything else (commons-collections, Spring AOP/beans/context,
 * com.sun.*, …) before construction, so a queue-injected blob cannot drive a deserialization gadget into
 * {@code readObject()}. The allowlist is deliberately broader than {@link AuthorizationBlobs} because session
 * attributes span more types; a too-tight filter would drop the SecurityContext and loop the user back to
 * login, which the live verification catches.
 */
public final class SessionBlobs {

    private static final Logger LOG = LogManager.getLogger(SessionBlobs.class);

    /**
     * The allowlist. Besides the packages, exactly two classes of {@code org.springframework.util}:
     * {@link org.springframework.util.LinkedMultiValueMap} and its superclass {@code MultiValueMapAdapter}, which
     * every {@code FlashMap} (the flash attributes of a redirect, e.g. the account console's "password changed")
     * holds its target request parameters in. Without them the whole session was dropped and the user was back on
     * the sign-in page after any console form.
     */
    private static final ObjectInputFilter FILTER = ObjectInputFilter.Config.createFilter(
            "maxbytes=8000000;maxdepth=60;maxrefs=200000;maxarray=200000;"
                    + "org.springframework.security.**;"
                    + "org.springframework.web.**;"
                    + "org.springframework.session.**;"
                    + "org.springframework.http.**;"
                    + "org.springframework.util.LinkedMultiValueMap;"
                    + "org.springframework.util.MultiValueMapAdapter;"
                    + "io.helixiam.**;"
                    + "java.**;"
                    + "!*");

    private SessionBlobs() {
    }

    /** Serialize a (serializable) attribute map to a base64 blob. */
    public static String serialize(final Map<String, Object> attributes) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(attributes instanceof Serializable ? attributes : new java.util.HashMap<>(attributes));
            oos.flush();
            return Base64.getEncoder().encodeToString(bos.toByteArray());
        } catch (final Exception e) {
            throw new IllegalStateException("Could not serialize session attributes: " + e.getMessage(), e);
        }
    }

    /**
     * Deserialize a base64 blob to the attribute map, or an empty map if absent/unreadable/filter-rejected. An
     * unreadable or rejected session is logged (WARN) with the rejected class name or the failure's type only, never
     * the session's contents: the user is signed out, and the log says why.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> deserialize(final String blob) {
        if (blob == null || blob.isBlank()) {
            return new java.util.HashMap<>();
        }
        final RecordingFilter filter = new RecordingFilter();
        try (ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(Base64.getDecoder().decode(blob)))) {
            ois.setObjectInputFilter(filter);
            final Object o = ois.readObject();
            return o instanceof Map ? (Map<String, Object>) o : new java.util.HashMap<>();
        } catch (final Exception e) {
            if (filter.rejectedClass != null) {
                LOG.warn("HTTP session dropped: its attributes hold {}, which the session store's allowlist rejects;"
                        + " the user has to sign in again", LogSafe.sanitize(filter.rejectedClass));
            } else if (filter.rejectedLimit) {
                LOG.warn("HTTP session dropped: its attributes exceed the session store's size or depth limits;"
                        + " the user has to sign in again");
            } else {
                LOG.warn("HTTP session dropped: its attributes could not be read ({}); the user has to sign in again",
                        LogSafe.sanitize(e.getClass().getName()));
            }
            return new java.util.HashMap<>();
        }
    }

    /** {@link #FILTER}, remembering what it rejected (a class name, or a size/depth limit) for the log line. */
    private static final class RecordingFilter implements ObjectInputFilter {

        private String rejectedClass;
        private boolean rejectedLimit;

        @Override
        public Status checkInput(final FilterInfo info) {
            final Status status = FILTER.checkInput(info);
            if (status == Status.REJECTED && rejectedClass == null && !rejectedLimit) {
                final Class<?> type = info.serialClass();
                if (type != null) {
                    rejectedClass = type.isArray() ? type.getComponentType().getName() + "[]" : type.getName();
                } else {
                    rejectedLimit = true;
                }
            }
            return status;
        }
    }
}
