package io.helixiam.authorization.service;

import io.helixiam.authorization.service.utils.PasswordUtils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordEncoderServiceTest {

    private final PasswordEncoderService service = new PasswordEncoderService();

    @Test
    void encode_producesArgon2idHash_thatVerifies() {
        final String hash = service.encode("s3cret-pw");

        assertTrue(hash.startsWith("$argon2id"), hash);
        assertTrue(service.isEncoded(hash));
        assertTrue(service.matches("s3cret-pw", hash, null));
        assertFalse(service.matches("wrong", hash, null));
        // Argon2 is salted, so two encodes of the same password differ.
        assertFalse(hash.equals(service.encode("s3cret-pw")));
    }

    @Test
    void matches_verifiesLegacySha256SaltCredential() {
        final String salt = PasswordUtils.generateSaltValue();
        final String legacyHash = PasswordUtils.preparePassword("old-pw", salt);

        assertFalse(service.isEncoded(legacyHash));
        assertTrue(service.matches("old-pw", legacyHash, salt));
        assertFalse(service.matches("old-pw", legacyHash, "different-salt"));
        assertFalse(service.matches("wrong", legacyHash, salt));
    }

    @Test
    void upgradeNeeded_trueForLegacy_falseForArgon2() {
        final String salt = PasswordUtils.generateSaltValue();
        final String legacyHash = PasswordUtils.preparePassword("p", salt);

        assertTrue(service.upgradeNeeded(legacyHash));
        assertFalse(service.upgradeNeeded(service.encode("p")));
    }

    @Test
    void matches_falseForNullInputs() {
        assertFalse(service.matches(null, "x", null));
        assertFalse(service.matches("x", null, null));
    }
}
