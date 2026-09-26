/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.mfa;

import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil;
import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.OptionalLong;
import java.util.function.LongSupplier;

/**
 * 1.0 item 6: TOTP (RFC 6238, SHA-1, 6 digits, 30 s steps) enrolment and verification.
 *
 * <ul>
 *   <li>A secret is generated per enrolment and only stored — with {@code mfa_enabled=true} — once the user has
 *       confirmed it with a valid code. Who created the user no longer matters.</li>
 *   <li>A code is accepted for the current step ±1 (30 s either side).</li>
 *   <li>Replay protection: the accepted step is recorded atomically and a code for the same or an earlier step
 *       is refused.</li>
 * </ul>
 */
@Service
public class TotpService {

    static final int STEP_SECONDS = TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS;
    private static final int DIGITS = TimeBasedOneTimePasswordUtil.DEFAULT_OTP_LENGTH;

    private final UserCredentialsRepository users;
    private final LongSupplier clock;

    @org.springframework.beans.factory.annotation.Autowired
    public TotpService(final UserCredentialsRepository users) {
        this(users, System::currentTimeMillis);
    }

    TotpService(final UserCredentialsRepository users, final LongSupplier clock) {
        this.users = users;
        this.clock = clock;
    }

    public String newSecret() {
        return TimeBasedOneTimePasswordUtil.generateBase32Secret();
    }

    /** {@code otpauth://totp/<issuer>:<account>?secret=…&issuer=<issuer>&digits=6&period=30}, properly encoded. */
    public static String otpauthUri(final String issuer, final String account, final String secret) {
        return "otpauth://totp/" + encode(issuer) + ":" + encode(account) + "?secret=" + secret
                + "&issuer=" + encode(issuer) + "&algorithm=SHA1&digits=" + DIGITS + "&period=" + STEP_SECONDS;
    }

    public boolean isEnrolled(final String userId) {
        return users.findByUserId(userId).map(u -> u.isMfaEnabled() && u.getMfaSecret() != null).orElse(false);
    }

    /** Confirms a pending enrolment: a valid code for {@code secret} stores it and turns TOTP on. */
    @Transactional
    public boolean confirmEnrolment(final String userId, final String secret, final String code) {
        final OptionalLong step = matchingStep(secret, code, Long.MIN_VALUE, clock.getAsLong());
        if (step.isEmpty()) {
            return false;
        }
        final UserCredentials user = users.findByUserId(userId).orElse(null);
        if (user == null) {
            return false;
        }
        user.setMfaSecret(secret);
        user.setMfaEnabled(true);
        user.setMfaLastStep(step.getAsLong());
        users.save(user);
        return true;
    }

    /** Verifies a sign-in code for an enrolled user, refusing replays. */
    public boolean verify(final String userId, final String code) {
        final UserCredentials user = users.findByUserId(userId).orElse(null);
        if (user == null || !user.isMfaEnabled() || user.getMfaSecret() == null) {
            return false;
        }
        final long last = user.getMfaLastStep() == null ? Long.MIN_VALUE : user.getMfaLastStep();
        final OptionalLong step = matchingStep(user.getMfaSecret(), code, last, clock.getAsLong());
        return step.isPresent() && users.advanceMfaStep(userId, step.getAsLong()) == 1;
    }

    /** The latest step within ±1 of now whose code matches and which is later than {@code lastStep}. */
    static OptionalLong matchingStep(final String secret, final String code, final long lastStep, final long nowMillis) {
        if (secret == null || code == null || !code.trim().matches("\\d{" + DIGITS + "}")) {
            return OptionalLong.empty();
        }
        final String candidate = code.trim();
        final long now = nowMillis / 1000L / STEP_SECONDS;
        for (long step = now + 1; step >= now - 1; step--) {
            if (step <= lastStep) {
                break;
            }
            try {
                final String expected = TimeBasedOneTimePasswordUtil.generateNumberString(secret,
                        step * STEP_SECONDS * 1000L, STEP_SECONDS, DIGITS);
                if (java.security.MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),
                        candidate.getBytes(StandardCharsets.US_ASCII))) {
                    return OptionalLong.of(step);
                }
            } catch (final GeneralSecurityException | IllegalArgumentException e) {
                return OptionalLong.empty();
            }
        }
        return OptionalLong.empty();
    }

    private static String encode(final String s) {
        return URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
