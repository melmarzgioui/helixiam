/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.persistence.security;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The at-rest converter for secret columns (TOTP secrets, realm signing keys, client secrets, …). A value that
 * cannot be decrypted is never handed back as if it were the secret: by default the read fails with a message that
 * names the cause but never the value. Reading legacy plaintext rows (written before DB_ENCRYPTION was set) is an
 * explicit, logged migration mode ({@code helix.allow-plaintext-secrets=true}).
 */
class AttributeEncryptionTest {

    private static final String KEY = "0123456789abcdef0123456789abcdef";
    private static final String OTHER_KEY = "fedcba9876543210fedcba9876543210";
    /** 16 characters: its GCM form (12 + 16 + 16 bytes) is no multiple of the AES block, so legacy ECB cannot "succeed" by chance. */
    private static final String SECRET = "JBSWY3DPEHPK3PXP";

    @AfterEach
    void clearPlaintextReads() {
        AttributeEncryption.plaintextReadsOnThisThread().clear();
    }

    @Test
    void currentFormat_roundTrips() {
        final AttributeEncryption enc = new AttributeEncryption(KEY, false);

        final String stored = enc.convertToDatabaseColumn(SECRET);

        assertThat(stored).isNotEqualTo(SECRET);
        assertThat(enc.convertToEntityAttribute(stored)).isEqualTo(SECRET);
    }

    @Test
    void aValueEncryptedWithAnotherKey_throws_andNeverRevealsTheValue() {
        final String stored = new AttributeEncryption(OTHER_KEY, false).convertToDatabaseColumn(SECRET);
        final AttributeEncryption enc = new AttributeEncryption(KEY, false);

        assertThatThrownBy(() -> enc.convertToEntityAttribute(stored))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("key")
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain(stored).doesNotContain(SECRET));
    }

    @Test
    void aTamperedValue_throws() {
        final AttributeEncryption enc = new AttributeEncryption(KEY, false);
        final byte[] raw = Base64.getDecoder().decode(enc.convertToDatabaseColumn(SECRET));
        raw[raw.length - 1] ^= 0x01;
        final String tampered = Base64.getEncoder().encodeToString(raw);

        assertThatThrownBy(() -> enc.convertToEntityAttribute(tampered)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void aPlaintextRow_throwsByDefault_namingTheCause_notTheValue() {
        final AttributeEncryption enc = new AttributeEncryption(KEY, false);
        final String pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----";

        assertThatThrownBy(() -> enc.convertToEntityAttribute(pem))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not encrypted")
                .hasMessageContaining("helix.allow-plaintext-secrets")
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"));
        assertThatThrownBy(() -> enc.convertToEntityAttribute(SECRET)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void aPlaintextRow_isReadWithTheFlag_andReEncryptedOnTheNextWrite() {
        final AttributeEncryption enc = new AttributeEncryption(KEY, true);

        final String read = enc.convertToEntityAttribute(SECRET);

        assertThat(read).isEqualTo(SECRET);
        // Recorded (by identity) so the load listener can name the entity and column in its warning.
        assertThat(AttributeEncryption.plaintextReadsOnThisThread()).containsExactly(read);
        final String rewritten = enc.convertToDatabaseColumn(read);
        assertThat(rewritten).isNotEqualTo(SECRET);
        assertThat(new AttributeEncryption(KEY, false).convertToEntityAttribute(rewritten)).isEqualTo(SECRET);
    }

    @Test
    void theLegacyAesFormat_stillDecrypts() throws Exception {
        final Cipher legacy = Cipher.getInstance("AES");
        legacy.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES"));
        final String stored = Base64.getEncoder().encodeToString(legacy.doFinal(SECRET.getBytes(StandardCharsets.UTF_8)));

        assertThat(new AttributeEncryption(KEY, false).convertToEntityAttribute(stored)).isEqualTo(SECRET);
    }

    @Test
    void withoutAKey_valuesPassThrough() {
        final AttributeEncryption enc = new AttributeEncryption(null, false);

        assertThat(enc.convertToDatabaseColumn(SECRET)).isEqualTo(SECRET);
        assertThat(enc.convertToEntityAttribute(SECRET)).isEqualTo(SECRET);
    }

    @Test
    void theOneArgumentConstructor_failsClosed() {
        assertThatThrownBy(() -> new AttributeEncryption(KEY).convertToEntityAttribute(SECRET))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void nullStaysNull() {
        assertThat(new AttributeEncryption(KEY, false).convertToEntityAttribute(null)).isNull();
    }

    @Test
    void theLoadListener_namesTheEntityAndAttribute_ofAPlaintextRead() {
        final String read = new AttributeEncryption(KEY, true).convertToEntityAttribute(SECRET);
        final Object[] state = {"realm-1", new String(SECRET), read};

        assertThat(PlaintextReadLogger.plaintextAttributes(state, new String[] {"realmId", "kid", "privateKey"}))
                .containsExactly("privateKey");
        assertThat(AttributeEncryption.plaintextReadsOnThisThread()).isEmpty();
    }
}
