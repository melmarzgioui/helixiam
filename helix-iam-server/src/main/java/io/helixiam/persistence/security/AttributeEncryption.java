/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.persistence.security;

import io.helixiam.persistence.DatabaseConstant;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.security.Security;
import java.util.Base64;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;

/**
 * Vendored verbatim (package renamed only) from
 * io.helixiam.subscriber.starter.database.security.AttributeEncryption.
 * Writes AES/GCM. The legacy plain-AES (AES/ECB) format of older values is read only until the startup
 * re-encryption ({@link LegacyEncryptionBackfill}) has rewritten them, then only with
 * {@code HELIX_DB_ENCRYPTION_ALLOW_LEGACY=true} (L5; this converts DB columns like TOTP secrets).
 *
 * <p>A stored value that neither format can decrypt is never returned as if it were the secret: the read fails
 * with an {@link IllegalStateException} that names the cause (the value is not encrypted, or the key changed or
 * the value was altered), never the value. A deployment that ran without {@code DB_ENCRYPTION} and still holds
 * plaintext rows sets {@code helix.security.db-encryption.migrate-plaintext=true}
 * ({@code HELIX_DB_ENCRYPTION_MIGRATE_PLAINTEXT}, its own flag, time-boxed by {@code ProductionReadinessCheck})
 * while it migrates: undecryptable values are then read as stored, each read is logged (with its entity and
 * attribute by {@link PlaintextReadLogger}), and the value is encrypted on the entity's next write. That mode also
 * hides a changed key, so it is turned off once the rows are re-encrypted. Its end date
 * ({@code HELIX_DB_ENCRYPTION_MIGRATE_UNTIL}, last day included) is enforced at every read, not only at startup: after
 * it, a plaintext read fails closed and logs an ERROR. A blank key means no key.
 */
@Converter
public class AttributeEncryption implements AttributeConverter<String, String> {
    private static final Logger LOG = LogManager.getLogger(DatabaseConstant.MODULE_NAME);

    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final String AES = "AES"; // Fallback mode
    private static final int GCM_IV_LENGTH = 12; // 12 bytes recommended for GCM
    private static final int GCM_TAG_LENGTH = 128; // 128-bit authentication tag

    /** Values read as stored (plaintext) on this thread, by identity, until {@link PlaintextReadLogger} names them. */
    private static final ThreadLocal<Set<String>> PLAINTEXT_READS = new ThreadLocal<>();
    /** Bound on {@link #PLAINTEXT_READS}: values read outside an entity load are never claimed. */
    private static final int MAX_TRACKED_PLAINTEXT_READS = 64;

    /** L5: see {@link #setLegacyFallback}. */
    private static volatile boolean legacyFallback = true;

    private final SecretKey key;
    private final SecretKey keyOld;
    private final boolean allowPlaintextRead;
    /** {@code HELIX_DB_ENCRYPTION_MIGRATE_UNTIL} (ISO date, last day included), or null when unset. */
    private final String migrateUntil;
    private final Clock clock;
    private final SecureRandom secureRandom = new SecureRandom();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /** Fails closed on an undecryptable value (no plaintext reads). */
    public AttributeEncryption(final String password) {
        this(password, false);
    }

    /** Plaintext reads with no end date (the dev profile; outside dev the startup check requires one). */
    public AttributeEncryption(final String password, final boolean allowPlaintextRead) {
        this(password, allowPlaintextRead, null, Clock.systemUTC());
    }

    @Autowired
    public AttributeEncryption(@Value("${database.encryption:#{null}}") final String password,
                               @Value("${helix.security.db-encryption.migrate-plaintext:false}")
                               final boolean allowPlaintextRead,
                               @Value("${helix.security.db-encryption.migrate-until:}") final String migrateUntil) {
        this(password, allowPlaintextRead, migrateUntil, Clock.systemUTC());
    }

    AttributeEncryption(final String password, final boolean allowPlaintextRead, final String migrateUntil,
                        final Clock clock) {
        this.allowPlaintextRead = allowPlaintextRead;
        this.migrateUntil = migrateUntil == null || migrateUntil.isBlank() ? null : migrateUntil.trim();
        this.clock = clock;
        if (password == null || password.isBlank()) { // DB_ENCRYPTION unset arrives as "": no key
            // Security review H2: with no key, every value below is stored/read as plaintext. That is a
            // legitimate opt-out for local dev, but it must never be silent — these columns hold realm
            // private signing keys and TOTP secrets.
            LOG.warn("=====================================================================");
            LOG.warn("database.encryption (DB_ENCRYPTION) is NOT set — at-rest attribute");
            LOG.warn("encryption is DISABLED. Realm private keys and TOTP secrets will be");
            LOG.warn("stored in PLAINTEXT. Set DB_ENCRYPTION for any non-local deployment.");
            LOG.warn("=====================================================================");
            key = null;
            keyOld = null;
        } else {
            key = generateKey(password);
            keyOld = new SecretKeySpec(password.getBytes(), "AES");
        }
    }

    private SecretKey generateKey(final String password) {
        return new SecretKeySpec(password.getBytes(), "AES");
    }

    @Override
    public String convertToDatabaseColumn(final String data) {
        if (key == null || data == null) {
            return data;
        }

        try {
            // Generate random IV for GCM
            final byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            final Cipher cipher = Cipher.getInstance(AES_GCM, "BC");
            final GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

            final byte[] encrypted = cipher.doFinal(data.getBytes());

            // Combine IV and encrypted data
            final byte[] combined = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (final Exception e) {
            // Security review H2: FAIL CLOSED. Returning `data` here silently persisted realm private
            // signing keys / TOTP secrets to the database in PLAINTEXT on any transient crypto error.
            // Failing the write is strictly safer than silently storing an unencrypted secret.
            LOG.error("At-rest encryption failed — refusing to store the value unencrypted", e);
            throw new IllegalStateException("At-rest encryption failed; refusing to persist plaintext", e);
        }
    }

    @Override
    public String convertToEntityAttribute(final String data) {
        if (key == null || data == null) {
            return data;
        }
        final String current = decryptGcm(data);
        if (current != null) {
            return current;
        }
        if (legacyFallback) {
            LOG.trace("GCM decryption failed, trying legacy mode");
            final String legacy = decryptLegacy(data);
            if (legacy != null) {
                return legacy;
            }
        } else if (decryptLegacy(data) != null) {
            // L5: after the startup re-encryption the legacy format is no longer read (unless the operator allows it).
            throw new IllegalStateException("An encrypted database column could not be read: it is in the legacy "
                    + "AES/ECB format, which is read only with HELIX_DB_ENCRYPTION_ALLOW_LEGACY=true "
                    + "(helix.security.db-encryption.allow-legacy). The startup re-encryption rewrites such rows.");
        }
        return undecryptable(data);
    }

    /**
     * L5 — the one-time re-encryption of the legacy format: {@code stored} in the current AES-GCM format when it is in
     * the legacy AES/ECB one, {@code null} when it already is current (or there is no key, or no value). Throws
     * {@link IllegalStateException} (never naming the value) when neither format reads it. Independent of the
     * runtime fallback ({@link #setLegacyFallback}).
     */
    public String reencryptLegacy(final String stored) {
        if (key == null || stored == null || decryptGcm(stored) != null) {
            return null;
        }
        final String plain = decryptLegacy(stored);
        if (plain == null) {
            throw new IllegalStateException("The value is neither in the current nor in the legacy format of this key");
        }
        return convertToDatabaseColumn(plain);
    }

    /**
     * Whether a value that is not in the current format is still tried in the legacy AES/ECB format. On by default, so
     * legacy rows read until the startup re-encryption ({@link LegacyEncryptionBackfill}) has rewritten them; then it is
     * {@code HELIX_DB_ENCRYPTION_ALLOW_LEGACY} (default false). Process-wide: it covers the JPA columns and the JDBC
     * stores that hold their own converter.
     */
    public static void setLegacyFallback(final boolean enabled) {
        legacyFallback = enabled;
    }

    public static boolean legacyFallbackEnabled() {
        return legacyFallback;
    }

    /** The value in the current AES-GCM format, or null when it is not (any failure). */
    private String decryptGcm(final String data) {
        try {
            final byte[] combined = Base64.getDecoder().decode(data);

            // Extract IV from the combined data
            final byte[] iv = new byte[GCM_IV_LENGTH];
            System.arraycopy(combined, 0, iv, 0, iv.length);

            // Extract encrypted data
            final byte[] encrypted = new byte[combined.length - GCM_IV_LENGTH];
            System.arraycopy(combined, iv.length, encrypted, 0, encrypted.length);

            final Cipher cipher = Cipher.getInstance(AES_GCM, "BC");
            final GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

            return new String(cipher.doFinal(encrypted));
        } catch (final Exception e) {
            return null;
        }
    }

    /**
     * The value in the legacy AES/ECB format, or null when it is not. ECB has no integrity check: a value under another
     * key passes the padding check about 1 time in 256, so the result must also be valid UTF-8 text (every secret this
     * converter stores is), which garbage almost never is (security review #10).
     */
    private String decryptLegacy(final String data) {
        try {
            final Cipher cipher = Cipher.getInstance(AES);
            cipher.init(Cipher.DECRYPT_MODE, keyOld);
            final byte[] plain = cipher.doFinal(Base64.getDecoder().decode(data));
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(plain)).toString();
        } catch (final Exception e) {
            return null;
        }
    }

    /**
     * Neither GCM nor the legacy format could decrypt {@code data}. Fail closed, unless the operator opted in to
     * reading legacy plaintext rows. Neither the exception nor the log ever carries the value.
     */
    private String undecryptable(final String data) {
        if (allowPlaintextRead && migrationWindowEnded()) {
            // The startup check only looks at the date once; a server that keeps running past it must stop reading
            // plaintext then, or the time box would end only at the next restart.
            LOG.error("Refused to read a plaintext value from an encrypted column: the plaintext migration window ended on "
                    + "{} (HELIX_DB_ENCRYPTION_MIGRATE_UNTIL). Unset HELIX_DB_ENCRYPTION_MIGRATE_PLAINTEXT once the rows "
                    + "are re-encrypted, or set a new end date and restart", LogSafeDate.of(migrateUntil));
            throw new IllegalStateException("An encrypted database column could not be read: it is not encrypted, and the "
                    + "plaintext migration window (HELIX_DB_ENCRYPTION_MIGRATE_UNTIL) has ended.");
        }
        if (allowPlaintextRead) {
            Set<String> reads = PLAINTEXT_READS.get();
            if (reads == null || reads.size() >= MAX_TRACKED_PLAINTEXT_READS) {
                reads = Collections.newSetFromMap(new IdentityHashMap<>());
                PLAINTEXT_READS.set(reads);
            }
            reads.add(data);
            LOG.warn("Read a plaintext value from an encrypted column (HELIX_DB_ENCRYPTION_MIGRATE_PLAINTEXT=true); it is "
                    + "encrypted on the entity's next write");
            return data;
        }
        final String cause = looksLikeCiphertext(data)
                ? "it cannot be decrypted with the current DB_ENCRYPTION key (the key changed, or the value was "
                        + "altered). Restore the key the value was written with"
                : "it is not encrypted (written before DB_ENCRYPTION was set). To read and re-encrypt such rows, "
                        + "set HELIX_DB_ENCRYPTION_MIGRATE_PLAINTEXT=true (helix.security.db-encryption.migrate-plaintext) "
                        + "with HELIX_DB_ENCRYPTION_MIGRATE_UNTIL until they are rewritten";
        throw new IllegalStateException("An encrypted database column could not be read: " + cause + ".");
    }

    /**
     * Whether the plaintext migration window is over: today (UTC) is after {@code HELIX_DB_ENCRYPTION_MIGRATE_UNTIL},
     * whose last day is included. An end date that is not an ISO date counts as over (fail closed); no end date at all
     * is the dev profile's unbounded mode (outside dev the server does not start without one).
     */
    private boolean migrationWindowEnded() {
        if (migrateUntil == null) {
            return false;
        }
        try {
            return LocalDate.now(clock).isAfter(LocalDate.parse(migrateUntil));
        } catch (final DateTimeParseException e) {
            return true;
        }
    }

    /** The configured end date for a log line: an ISO date as is, anything else replaced (never echoed). */
    private static final class LogSafeDate {
        private LogSafeDate() {
        }

        static String of(final String value) {
            return value != null && value.matches("\\d{4}-\\d{2}-\\d{2}") ? value : "(not an ISO date)";
        }
    }

    /** Base64 of at least one AES block: what this converter writes (GCM: IV + tag; legacy: whole blocks). */
    private static boolean looksLikeCiphertext(final String data) {
        try {
            final int length = Base64.getDecoder().decode(data).length;
            return length >= GCM_IV_LENGTH + GCM_TAG_LENGTH / 8 || length > 0 && length % 16 == 0;
        } catch (final IllegalArgumentException e) {
            return false;
        }
    }

    /** The values this thread read as plaintext and that no entity load has claimed yet (identity set). */
    /** Forgets this thread's unclaimed plaintext reads (removes the ThreadLocal). */
    static void clearPlaintextReads() {
        PLAINTEXT_READS.remove();
    }

    /** This thread's unclaimed plaintext reads, or null when there are none (no ThreadLocal is created). */
    static Set<String> trackedPlaintextReads() {
        return PLAINTEXT_READS.get();
    }

    /** This thread's unclaimed plaintext reads (identity set; empty when none). */
    static Set<String> plaintextReadsOnThisThread() {
        final Set<String> reads = PLAINTEXT_READS.get();
        return reads == null ? Set.of() : reads;
    }
}
