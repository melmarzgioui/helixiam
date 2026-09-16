package group.mfnr.authorization.security;

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;

/**
 * Helix IAM (Q1/Q2): (de)serialization of an {@link OAuth2Authorization} to/from the opaque base64 blob the
 * queue-backed store persists in the subscriber. The publisher owns this so the subscriber treats the blob as
 * bytes. Reused by the token store ({@code QueueOAuth2AuthorizationService}) and the SSO readers
 * ({@code QueueSsoSessionStore} / {@code QueueSessionStore}).
 *
 * <p>Security: deserialization is constrained by a strict JEP-290 allowlist — only the known
 * OAuth2Authorization object graph (Spring Security/OAuth2, our own principal/claim types, JDK value types)
 * may be reconstructed; gadget classes (commons-collections, Spring AOP/beans, com.sun.*, …) are rejected
 * before construction, so a queue-injected blob cannot drive a deserialization gadget into {@code readObject()}.
 */
public final class AuthorizationBlobs {

    private static final ObjectInputFilter FILTER = ObjectInputFilter.Config.createFilter(
            "maxbytes=5000000;maxdepth=50;maxrefs=100000;maxarray=100000;"
                    + "org.springframework.security.**;"
                    + "group.mfnr.**;"
                    + "java.util.**;java.time.**;java.lang.**;java.net.**;"
                    + "!*");

    private AuthorizationBlobs() {
    }

    /** Serialize an authorization to a base64 blob. */
    public static String serialize(final OAuth2Authorization authorization) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(authorization);
            oos.flush();
            return Base64.getEncoder().encodeToString(bos.toByteArray());
        } catch (final Exception e) {
            throw new IllegalStateException("Could not serialize authorization: " + e.getMessage(), e);
        }
    }

    /** Deserialize a base64 blob to an authorization, or {@code null} if absent/unreadable/filter-rejected. */
    public static OAuth2Authorization deserialize(final String blob) {
        if (blob == null || blob.isBlank()) {
            return null;
        }
        try (ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(Base64.getDecoder().decode(blob)))) {
            ois.setObjectInputFilter(FILTER);
            return (OAuth2Authorization) ois.readObject();
        } catch (final Exception e) {
            // A blob we can't read (class change across deploys, or a filter-rejected payload) → treated as
            // absent. For the token store that means re-login; for the SSO readers it's just skipped.
            return null;
        }
    }
}
