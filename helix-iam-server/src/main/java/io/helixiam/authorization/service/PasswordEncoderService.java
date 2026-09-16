package io.helixiam.authorization.service;

import io.helixiam.authorization.service.utils.PasswordUtils;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Hashes and verifies user passwords.
 *
 * <p>New passwords are hashed with <b>Argon2id</b> (OWASP-aligned parameters). Legacy
 * credentials created by the old scheme (SHA-256 over {@code password + salt}, stored
 * with a separate salt column) are still verified, then transparently re-hashed to
 * Argon2id on the next successful login (see {@link #upgradeNeeded}). This lets the
 * store migrate without forcing a password reset.
 *
 * <p>Argon2id hashes are self-identifying (they start with {@code $argon2}) and embed
 * their own salt, so the legacy {@code password_salt_value} column is left {@code null}
 * for migrated/new credentials.
 */
@Service
public class PasswordEncoderService {

    /** Prefix of a PHC-format Argon2 hash, e.g. {@code $argon2id$v=19$m=19456,t=2,p=1$...}. */
    private static final String ARGON2_PREFIX = "$argon2";

    // OWASP-aligned Argon2id defaults (saltLength=16, hashLength=32, parallelism=1,
    // memory=19456 KiB, iterations=2) as shipped by Spring Security.
    private final PasswordEncoder argon2 = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();

    /** Hashes a raw password with Argon2id. */
    public String encode(final String rawPassword) {
        return argon2.encode(rawPassword);
    }

    /** Whether the stored value is already an Argon2id hash. */
    public boolean isEncoded(final String storedHash) {
        return storedHash != null && storedHash.startsWith(ARGON2_PREFIX);
    }

    /**
     * Verifies a raw password against the stored credential, supporting both Argon2id and
     * the legacy SHA-256+salt scheme.
     *
     * @param rawPassword the submitted password
     * @param storedHash  the stored hash (Argon2id PHC string or legacy Base64 SHA-256)
     * @param legacySalt  the legacy per-user salt (ignored for Argon2id hashes)
     * @return {@code true} if the password matches
     */
    public boolean matches(final String rawPassword, final String storedHash, final String legacySalt) {
        if (rawPassword == null || storedHash == null) {
            return false;
        }
        if (isEncoded(storedHash)) {
            return argon2.matches(rawPassword, storedHash);
        }
        final String legacyHash = PasswordUtils.preparePassword(rawPassword, legacySalt);
        return legacyHash != null && MessageDigest.isEqual(
                legacyHash.getBytes(StandardCharsets.UTF_8),
                storedHash.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Whether a stored credential that just verified should be upgraded to Argon2id
     * (i.e. it is still in the legacy format).
     */
    public boolean upgradeNeeded(final String storedHash) {
        return !isEncoded(storedHash);
    }
}
