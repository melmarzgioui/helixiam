package group.mfnr.authorization.service.utils;


import com.nimbusds.jose.util.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class PasswordUtils {

    private static final Logger LOG = LogManager.getLogger(PasswordUtils.class);

    private PasswordUtils() {
        throw new IllegalAccessError();
    }

    public static String generateSaltValue() {

        try {
            final SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            final byte[] bytes = new byte[16];
            secureRandom.nextBytes(bytes);
            return Base64.encode(bytes).toString();
        } catch (final NoSuchAlgorithmException e) {
            LOG.error("Failed to generate salt value '{}'", e.getMessage());
        }

        return null;
    }

    public static String preparePassword(final String password, final String saltValue) {

        try {
            final String digestInput = password + saltValue;

            final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] byteValue = messageDigest.digest(digestInput.getBytes());
            return Base64.encode(byteValue).toString();
        } catch (final NoSuchAlgorithmException e) {
            LOG.error("Failed to generate password '{}'", e.getMessage());
        }

        return null;
    }

}
