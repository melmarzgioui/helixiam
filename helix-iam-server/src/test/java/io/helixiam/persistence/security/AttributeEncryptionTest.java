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
 * explicit, logged and time-boxed migration mode ({@code helix.security.db-encryption.migrate-plaintext=true}).
 */
class AttributeEncryptionTest {

    private static final String KEY = "0123456789abcdef0123456789abcdef";
    private static final String OTHER_KEY = "fedcba9876543210fedcba9876543210";
    /** 16 characters: its GCM form (12 + 16 + 16 bytes) is no multiple of the AES block, so legacy ECB cannot "succeed" by chance. */
    private static final String SECRET = "JBSWY3DPEHPK3PXP";

    @AfterEach
    void clearPlaintextReads() {
        AttributeEncryption.clearPlaintextReads();
        AttributeEncryption.setLegacyFallback(true); // the process default until the startup re-encryption has run
    }

    private static String legacyEcb(final String key, final String value) throws Exception {
        final Cipher legacy = Cipher.getInstance("AES");
        legacy.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES"));
        return Base64.getEncoder().encodeToString(legacy.doFinal(value.getBytes(StandardCharsets.UTF_8)));
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
                .hasMessageContaining("HELIX_DB_ENCRYPTION_MIGRATE_PLAINTEXT")
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

    // --- the migration window is enforced at runtime, not only at startup -----------------------------------------

    private static java.time.Clock at(final String isoDate) {
        return java.time.Clock.fixed(java.time.LocalDate.parse(isoDate).atStartOfDay(java.time.ZoneOffset.UTC)
                .plusHours(12).toInstant(), java.time.ZoneOffset.UTC);
    }

    @Test
    void withinTheMigrationWindow_aPlaintextRowIsRead_upToAndIncludingTheLastDay() {
        assertThat(new AttributeEncryption(KEY, true, "2026-10-20", at("2026-10-13")).convertToEntityAttribute(SECRET))
                .isEqualTo(SECRET);
        assertThat(new AttributeEncryption(KEY, true, "2026-10-20", at("2026-10-20")).convertToEntityAttribute(SECRET))
                .isEqualTo(SECRET);
    }

    @Test
    void afterTheMigrationWindow_aPlaintextReadFailsClosed_andLogsAnError() {
        final AttributeEncryption enc = new AttributeEncryption(KEY, true, "2026-10-20", at("2026-10-21"));

        try (io.helixiam.testsupport.LogCapture log =
                     io.helixiam.testsupport.LogCapture.named(io.helixiam.persistence.DatabaseConstant.MODULE_NAME)) {
            assertThatThrownBy(() -> enc.convertToEntityAttribute(SECRET))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("HELIX_DB_ENCRYPTION_MIGRATE_UNTIL")
                    .satisfies(e -> assertThat(e.getMessage()).doesNotContain(SECRET));
            assertThat(log.text()).contains("migration window ended on 2026-10-20").doesNotContain(SECRET);
        }
        assertThat(AttributeEncryption.plaintextReadsOnThisThread()).isEmpty();
    }

    @Test
    void aMigrationWindowThatIsNotADate_failsClosed() {
        assertThatThrownBy(() -> new AttributeEncryption(KEY, true, "next week", at("2026-10-13"))
                .convertToEntityAttribute(SECRET)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void theWindowEndsWhileRunning_withTheSameConverterInstance() {
        final java.util.concurrent.atomic.AtomicReference<java.time.Clock> clock =
                new java.util.concurrent.atomic.AtomicReference<>(at("2026-10-20"));
        final java.time.Clock moving = new java.time.Clock() {
            @Override
            public java.time.ZoneId getZone() {
                return java.time.ZoneOffset.UTC;
            }

            @Override
            public java.time.Clock withZone(final java.time.ZoneId zone) {
                return this;
            }

            @Override
            public java.time.Instant instant() {
                return clock.get().instant();
            }
        };
        final AttributeEncryption enc = new AttributeEncryption(KEY, true, "2026-10-20", moving);
        assertThat(enc.convertToEntityAttribute(SECRET)).isEqualTo(SECRET);

        clock.set(at("2026-10-21"));

        assertThatThrownBy(() -> enc.convertToEntityAttribute(SECRET)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void theLegacyAesFormat_stillDecrypts_whileTheFallbackIsOn() throws Exception {
        AttributeEncryption.setLegacyFallback(true);
        final String stored = legacyEcb(KEY, SECRET);

        assertThat(new AttributeEncryption(KEY, false).convertToEntityAttribute(stored)).isEqualTo(SECRET);
    }

    // --- L5: the legacy AES/ECB format is re-encrypted once, then its fallback is off --------------------------------

    @Test
    void withTheFallbackOff_aLegacyRowFailsClosed_namingTheFlag_notTheValue() throws Exception {
        final String stored = legacyEcb(KEY, SECRET);
        AttributeEncryption.setLegacyFallback(false);

        assertThatThrownBy(() -> new AttributeEncryption(KEY, false).convertToEntityAttribute(stored))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("HELIX_DB_ENCRYPTION_ALLOW_LEGACY")
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain(SECRET).doesNotContain(stored));
        // The plaintext-migration mode does not reopen it either: a legacy value is not plaintext.
        assertThatThrownBy(() -> new AttributeEncryption(KEY, true).convertToEntityAttribute(stored))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void reencryptLegacy_turnsALegacyValueIntoTheCurrentFormat() throws Exception {
        final AttributeEncryption enc = new AttributeEncryption(KEY, false);
        final String stored = legacyEcb(KEY, SECRET);
        AttributeEncryption.setLegacyFallback(false); // the re-encryption never depends on the runtime fallback

        final String rewritten = enc.reencryptLegacy(stored);

        assertThat(rewritten).isNotNull().isNotEqualTo(stored);
        assertThat(enc.convertToEntityAttribute(rewritten)).isEqualTo(SECRET);
    }

    @Test
    void reencryptLegacy_leavesACurrentValueAlone_andRefusesAnUnreadableOne() {
        final AttributeEncryption enc = new AttributeEncryption(KEY, false);

        assertThat(enc.reencryptLegacy(enc.convertToDatabaseColumn(SECRET))).isNull();
        assertThat(enc.reencryptLegacy(null)).isNull();
        assertThatThrownBy(() -> enc.reencryptLegacy(new AttributeEncryption(OTHER_KEY, false)
                .convertToDatabaseColumn(SECRET))).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> enc.reencryptLegacy(SECRET)).isInstanceOf(IllegalStateException.class);
        assertThat(new AttributeEncryption(null, false).reencryptLegacy(SECRET)).as("no key: nothing to do").isNull();
    }

    @Test
    void aLegacyDecryptionThatIsNotUtf8_isNotTakenForTheSecret() throws Exception {
        // ECB "decrypting" a value under the wrong key passes the padding check about 1 time in 256 and yields bytes
        // that are not text; such a result must not be returned (or re-encrypted) as the secret.
        final Cipher legacy = Cipher.getInstance("AES");
        legacy.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES"));
        final String notText = Base64.getEncoder().encodeToString(legacy.doFinal(new byte[] {(byte) 0xC3, (byte) 0x28,
                (byte) 0xFF, (byte) 0xFE}));
        final AttributeEncryption enc = new AttributeEncryption(KEY, false);

        assertThatThrownBy(() -> enc.convertToEntityAttribute(notText)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> enc.reencryptLegacy(notText)).isInstanceOf(IllegalStateException.class);
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

    // --- review #11: an empty DB_ENCRYPTION is "no key" -----------------------------------------------

    @Test
    void anEmptyOrBlankKey_isNoKey() {
        for (final String blank : new String[] {"", "  "}) {
            final AttributeEncryption enc = new AttributeEncryption(blank, false);
            assertThat(enc.convertToDatabaseColumn(SECRET)).isEqualTo(SECRET);
            assertThat(enc.convertToEntityAttribute(SECRET)).isEqualTo(SECRET);
        }
    }

    // --- review #12: the per-thread record of plaintext reads is removed after use -------------------

    @Test
    void claimingTheLastPlaintextRead_removesTheThreadLocal() {
        final String read = new AttributeEncryption(KEY, true).convertToEntityAttribute(SECRET);
        assertThat(AttributeEncryption.trackedPlaintextReads()).isNotNull();

        PlaintextReadLogger.plaintextAttributes(new Object[] {read}, new String[] {"secret"});

        assertThat(AttributeEncryption.trackedPlaintextReads()).as("ThreadLocal removed").isNull();
    }

    @Test
    void theEndOfATransaction_removesAnyUnclaimedPlaintextReads() {
        new AttributeEncryption(KEY, true).convertToEntityAttribute(SECRET);

        new PlaintextReadLogger().afterTransactionCompletion(null);

        assertThat(AttributeEncryption.trackedPlaintextReads()).isNull();
    }

    @Test
    void noPlaintextRead_createsNoThreadLocal() {
        PlaintextReadLogger.plaintextAttributes(new Object[] {"x"}, new String[] {"a"});
        new AttributeEncryption(KEY, false).convertToEntityAttribute(new AttributeEncryption(KEY, false)
                .convertToDatabaseColumn(SECRET));

        assertThat(AttributeEncryption.trackedPlaintextReads()).isNull();
    }

    // --- review #4: plaintext reads have their own flag ----------------------------------------------

    @Test
    void theSpringConstructor_readsTheDedicatedMigrationFlag_notAllowPlaintextSecrets() throws Exception {
        final java.lang.reflect.Constructor<?> ctor = java.util.Arrays.stream(AttributeEncryption.class.getConstructors())
                .filter(c -> c.isAnnotationPresent(org.springframework.beans.factory.annotation.Autowired.class))
                .findFirst().orElseThrow();
        final java.util.List<String> values = java.util.Arrays.stream(ctor.getParameters())
                .map(p -> p.getAnnotation(org.springframework.beans.factory.annotation.Value.class).value()).toList();

        assertThat(values).contains("${helix.security.db-encryption.migrate-plaintext:false}",
                "${helix.security.db-encryption.migrate-until:}");
    }
}
