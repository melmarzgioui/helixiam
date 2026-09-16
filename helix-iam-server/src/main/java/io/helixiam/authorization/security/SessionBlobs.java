package io.helixiam.authorization.security;

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

    private static final ObjectInputFilter FILTER = ObjectInputFilter.Config.createFilter(
            "maxbytes=8000000;maxdepth=60;maxrefs=200000;maxarray=200000;"
                    + "org.springframework.security.**;"
                    + "org.springframework.web.**;"
                    + "org.springframework.session.**;"
                    + "org.springframework.http.**;"
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

    /** Deserialize a base64 blob to the attribute map, or an empty map if absent/unreadable/filter-rejected. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> deserialize(final String blob) {
        if (blob == null || blob.isBlank()) {
            return new java.util.HashMap<>();
        }
        try (ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(Base64.getDecoder().decode(blob)))) {
            ois.setObjectInputFilter(FILTER);
            final Object o = ois.readObject();
            return o instanceof Map ? (Map<String, Object>) o : new java.util.HashMap<>();
        } catch (final Exception e) {
            return new java.util.HashMap<>();
        }
    }
}
