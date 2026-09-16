package group.mfnr.authorization.service.provisioning;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Helix IAM E11: opaque provisioning-token generation + hashing. Tokens are high-entropy URL-safe random
 * strings; only their SHA-256 hex digest is persisted, so a DB leak never yields a usable token. Constant-
 * time comparison on verify.
 */
public final class ProvisioningTokens {

    private static final SecureRandom RANDOM = new SecureRandom();

    private ProvisioningTokens() {
    }

    /** A fresh 256-bit URL-safe opaque token (returned to the caller exactly once). */
    public static String generate() {
        final byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** SHA-256 hex of a token (what we store). */
    public static String hash(final String token) {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Constant-time check that {@code presented} hashes to {@code expectedHash}. */
    public static boolean matches(final String presented, final String expectedHash) {
        if (presented == null || expectedHash == null) {
            return false;
        }
        return MessageDigest.isEqual(
                hash(presented).getBytes(StandardCharsets.UTF_8),
                expectedHash.getBytes(StandardCharsets.UTF_8));
    }
}
