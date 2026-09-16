package io.helixiam.persistence.security;

import io.helixiam.persistence.DatabaseConstant;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

/**
 * Vendored verbatim (package renamed only) from
 * io.helixiam.subscriber.starter.database.security.AttributeEncryption.
 * AES/GCM (with a legacy plain-AES fallback for decrypting older values) semantics preserved
 * exactly, byte-for-byte, per the Task 1 constraint (this converts DB columns like TOTP secrets).
 */
@Converter
public class AttributeEncryption implements AttributeConverter<String, String> {
    private static final Logger LOG = LogManager.getLogger(DatabaseConstant.MODULE_NAME);

    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final String AES = "AES"; // Fallback mode
    private static final int GCM_IV_LENGTH = 12; // 12 bytes recommended for GCM
    private static final int GCM_TAG_LENGTH = 128; // 128-bit authentication tag

    private final SecretKey key;
    private final SecretKey keyOld;
    private final SecureRandom secureRandom = new SecureRandom();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public AttributeEncryption(@Value("${database.encryption:#{null}}") final String password) {
        if (password == null) {
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
            LOG.error("Encryption failed");
            return data; // Fallback to plaintext
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
        if (keyOld == null) {
            return data;
        }

        try {
            final Cipher cipher = Cipher.getInstance(AES);
            cipher.init(Cipher.DECRYPT_MODE, keyOld);

            return new String(cipher.doFinal(Base64.getDecoder().decode(data)));
        } catch (final Exception e) {
            LOG.trace("Legacy decryption failed, returning plaintext");
            return data;
        }
    }
}
