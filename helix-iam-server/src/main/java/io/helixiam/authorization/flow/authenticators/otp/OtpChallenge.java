/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.authenticators.otp;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Helix IAM E3.1: a one-time-code challenge shared by the SMS and Email factors. Holds only the
 * salted hash of the code (never the plaintext), a TTL, and a decrementing attempt counter; it is
 * single-use. Serializable so it can live in the (JDBC/Redis) login session across the
 * challenge→response round-trip. Time is injected so behaviour is deterministic.
 */
public class OtpChallenge implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final SecureRandom RANDOM = new SecureRandom();

    private String salt;
    private String codeHash;
    private long expiresAtMs;
    private int attemptsRemaining;

    protected OtpChallenge() {
    }

    public static OtpChallenge issue(final String code, final long ttlMs, final int maxAttempts, final long nowMs) {
        final OtpChallenge challenge = new OtpChallenge();
        final byte[] saltBytes = new byte[16];
        RANDOM.nextBytes(saltBytes);
        challenge.salt = Base64.getEncoder().encodeToString(saltBytes);
        challenge.codeHash = hash(code, challenge.salt);
        challenge.expiresAtMs = nowMs + ttlMs;
        challenge.attemptsRemaining = maxAttempts;
        return challenge;
    }

    /** True only for the correct code, before expiry, with attempts left. Always spends an attempt. */
    public boolean verify(final String submitted, final long nowMs) {
        if (isExhausted(nowMs)) {
            return false;
        }
        attemptsRemaining--;
        return MessageDigest.isEqual(
                codeHash.getBytes(StandardCharsets.UTF_8),
                hash(submitted, salt).getBytes(StandardCharsets.UTF_8));
    }

    public boolean isExhausted(final long nowMs) {
        return attemptsRemaining <= 0 || nowMs >= expiresAtMs;
    }

    public String codeHash() {
        return codeHash;
    }

    public int attemptsRemaining() {
        return attemptsRemaining;
    }

    private static String hash(final String code, final String salt) {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(salt.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(digest.digest(code.getBytes(StandardCharsets.UTF_8)));
        } catch (final Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
