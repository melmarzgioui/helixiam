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
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;

/**
 * Vendored verbatim (package renamed only) from
 * io.helixiam.subscriber.starter.database.security.AttributeEncryption.
 * AES/GCM (with a legacy plain-AES fallback for decrypting older values) semantics preserved
 * exactly, byte-for-byte, per the Task 1 constraint (this converts DB columns like TOTP secrets).
 *
 * <p>A stored value that neither format can decrypt is never returned as if it were the secret: the read fails
 * with an {@link IllegalStateException} that names the cause (the value is not encrypted, or the key changed or
 * the value was altered), never the value. A deployment that ran without {@code DB_ENCRYPTION} and still holds
 * plaintext rows sets {@code helix.allow-plaintext-secrets=true} ({@code HELIX_ALLOW_PLAINTEXT_SECRETS}) while it
 * migrates: undecryptable values are then read as stored, each read is logged with its entity and attribute
 * ({@link PlaintextReadLogger}), and the value is encrypted on the entity's next write. That mode also hides a
 * changed key, so it is turned off once the rows are re-encrypted.
 */
@Converter
public class AttributeEncryption implements AttributeConverter<String, String> {
    private static final Logger LOG = LogManager.getLogger(DatabaseConstant.MODULE_NAME);

    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final String AES = "AES"; // Fallback mode
    private static final int GCM_IV_LENGTH = 12; // 12 bytes recommended for GCM
    private static final int GCM_TAG_LENGTH = 128; // 128-bit authentication tag

    /** Values read as stored (plaintext) on this thread, by identity, until {@link PlaintextReadLogger} names them. */
    private static final ThreadLocal<Set<String>> PLAINTEXT_READS =
            ThreadLocal.withInitial(() -> Collections.newSetFromMap(new IdentityHashMap<>()));
    /** Bound on {@link #PLAINTEXT_READS}: values read outside an entity load are never claimed. */
    private static final int MAX_TRACKED_PLAINTEXT_READS = 64;

    private final SecretKey key;
    private final SecretKey keyOld;
    private final boolean allowPlaintextRead;
    private final SecureRandom secureRandom = new SecureRandom();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /** Fails closed on an undecryptable value (no plaintext reads). */
    public AttributeEncryption(final String password) {
        this(password, false);
    }

    @Autowired
    public AttributeEncryption(@Value("${database.encryption:#{null}}") final String password,
                               @Value("${helix.allow-plaintext-secrets:false}") final boolean allowPlaintextRead) {
        this.allowPlaintextRead = allowPlaintextRead;
        if (password == null) {
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

        try {
            final byte[] combined = Base64.getDecoder().decode(data);

            // Extract IV from the combined data
            final byte[] iv = new byte[GCM_IV_LENGTH];
            System.arraycopy(combined, 0, iv, 0, iv.length);

            // Extract encrypted data
            byte[] encrypted = new byte[combined.length - GCM_IV_LENGTH];
            System.arraycopy(combined, iv.length, encrypted, 0, encrypted.length);

            final Cipher cipher = Cipher.getInstance(AES_GCM, "BC");
            final GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

            return new String(cipher.doFinal(encrypted));
        } catch (final Exception e) {
            LOG.trace("GCM decryption failed, trying legacy mode");
            return tryLegacyDecryption(data);
        }
    }

    private String tryLegacyDecryption(final String data) {
        try {
            final Cipher cipher = Cipher.getInstance(AES);
            cipher.init(Cipher.DECRYPT_MODE, keyOld);

            return new String(cipher.doFinal(Base64.getDecoder().decode(data)));
        } catch (final Exception e) {
            return undecryptable(data);
        }
    }

    /**
     * Neither GCM nor the legacy format could decrypt {@code data}. Fail closed, unless the operator opted in to
     * reading legacy plaintext rows. Neither the exception nor the log ever carries the value.
     */
    private String undecryptable(final String data) {
        if (allowPlaintextRead) {
            final Set<String> reads = PLAINTEXT_READS.get();
            if (reads.size() >= MAX_TRACKED_PLAINTEXT_READS) {
                reads.clear();
            }
            reads.add(data);
            LOG.debug("Read an encrypted column's stored value as plaintext (helix.allow-plaintext-secrets=true)");
            return data;
        }
        final String cause = looksLikeCiphertext(data)
                ? "it cannot be decrypted with the current DB_ENCRYPTION key (the key changed, or the value was "
                        + "altered). Restore the key the value was written with"
                : "it is not encrypted (written before DB_ENCRYPTION was set). To read and re-encrypt such rows, "
                        + "set helix.allow-plaintext-secrets=true (HELIX_ALLOW_PLAINTEXT_SECRETS) until they are rewritten";
        throw new IllegalStateException("An encrypted database column could not be read: " + cause + ".");
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
    static Set<String> plaintextReadsOnThisThread() {
        return PLAINTEXT_READS.get();
    }
}
