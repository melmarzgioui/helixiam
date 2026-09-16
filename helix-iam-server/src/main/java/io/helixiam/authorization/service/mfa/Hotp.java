package io.helixiam.authorization.service.mfa;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;

/**
 * Helix IAM E3.4: HMAC-based one-time password (RFC 4226). Stateless; the counter is managed by
 * {@code HotpService}.
 */
public final class Hotp {

    private static final int[] POW10 = {1, 10, 100, 1000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000};

    private Hotp() {
    }

    public static String generate(final byte[] secret, final long counter, final int digits) {
        try {
            final Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(secret, "HmacSHA1"));
            final byte[] hash = mac.doFinal(ByteBuffer.allocate(8).putLong(counter).array());

            // RFC 4226 dynamic truncation.
            final int offset = hash[hash.length - 1] & 0x0F;
            final int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);

            final int otp = binary % POW10[digits];
            return String.format("%0" + digits + "d", otp);
        } catch (final Exception e) {
            throw new IllegalStateException("HmacSHA1 unavailable", e);
        }
    }
}
