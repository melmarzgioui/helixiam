package io.helixiam.authorization.flow.authenticators.otp;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E3.1: a one-time code challenge for the SMS/Email factors. Stores only the hashed
 * code, enforces a TTL and an attempt cap, and is single-use. Time is injected so the rules are
 * deterministic in tests.
 */
class OtpChallengeTest {

    private static final long T0 = 1_000_000L;
    private static final long TTL = 300_000L; // 5 min
    private static final int MAX_ATTEMPTS = 3;

    private OtpChallenge issue() {
        return OtpChallenge.issue("123456", TTL, MAX_ATTEMPTS, T0);
    }

    @Test
    void correctCodeWithinTtl_verifies() {
        assertThat(issue().verify("123456", T0 + 1000)).isTrue();
    }

    @Test
    void doesNotStoreThePlaintextCode() {
        assertThat(issue().codeHash()).isNotNull().isNotEqualTo("123456");
    }

    @Test
    void wrongCode_fails_andSpendsAnAttempt() {
        OtpChallenge challenge = issue();

        assertThat(challenge.verify("000000", T0 + 1000)).isFalse();
        assertThat(challenge.attemptsRemaining()).isEqualTo(MAX_ATTEMPTS - 1);
    }

    @Test
    void expiredCode_fails_evenWhenCorrect() {
        assertThat(issue().verify("123456", T0 + TTL + 1)).isFalse();
    }

    @Test
    void afterMaxWrongAttempts_isExhausted_andFurtherVerifyFails() {
        OtpChallenge challenge = issue();

        for (int i = 0; i < MAX_ATTEMPTS; i++) {
            challenge.verify("000000", T0 + 1000);
        }

        assertThat(challenge.isExhausted(T0 + 1000)).isTrue();
        assertThat(challenge.verify("123456", T0 + 1000)).isFalse(); // correct, but no attempts left
    }
}
