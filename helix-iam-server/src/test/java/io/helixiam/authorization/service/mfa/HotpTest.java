package io.helixiam.authorization.service.mfa;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E3.4: HMAC-based one-time password (RFC 4226). Pinned to the RFC's published test
 * vectors for secret "12345678901234567890", counters 0..9, 6 digits.
 */
class HotpTest {

    private static final byte[] SECRET = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

    @Test
    void matchesRfc4226TestVectors() {
        final String[] expected = {
                "755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"};
        for (int counter = 0; counter < expected.length; counter++) {
            assertThat(Hotp.generate(SECRET, counter, 6))
                    .as("counter %d", counter)
                    .isEqualTo(expected[counter]);
        }
    }

    @Test
    void zeroPadsToTheRequestedDigits() {
        assertThat(Hotp.generate(SECRET, 0, 8)).hasSize(8);
        assertThat(Hotp.generate(SECRET, 0, 6)).hasSize(6);
    }
}
