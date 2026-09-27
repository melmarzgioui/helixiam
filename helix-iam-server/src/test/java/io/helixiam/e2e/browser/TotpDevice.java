/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil;

import java.util.List;

/**
 * An authenticator app holding one TOTP secret. The server accepts the current 30 s step ±1 and refuses a step
 * it has already accepted (replay protection), so {@link #nextCode()} hands out strictly increasing steps and,
 * when all acceptable steps are used up, waits for the clock (at most one step, 30 s).
 */
public final class TotpDevice {

    private static final int STEP = TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS;

    private final String secret;
    private volatile List<String> recoveryCodes = List.of();
    private long lastStep = Long.MIN_VALUE;

    public TotpDevice(final String secret) {
        this.secret = secret;
    }

    void recoveryCodes(final List<String> codes) {
        this.recoveryCodes = List.copyOf(codes);
    }

    public String secret() {
        return secret;
    }

    /** The recovery codes shown once after enrolment (empty when the page was not reached). */
    public List<String> recoveryCodes() {
        return recoveryCodes;
    }

    /** A code the server will accept now and that was never handed out before. */
    public synchronized String nextCode() {
        final long step = Math.max(currentStep(), lastStep + 1);
        while (step > currentStep() + 1) {
            final long msIntoStep = System.currentTimeMillis() % (STEP * 1000L);
            sleep(STEP * 1000L - msIntoStep + 50);
        }
        lastStep = step;
        return codeAt(secret, step);
    }

    /** The code of {@code secret} for time step {@code step}. */
    public static String codeAt(final String secret, final long step) {
        try {
            return TimeBasedOneTimePasswordUtil.generateNumberString(secret, step * STEP * 1000L, STEP,
                    TimeBasedOneTimePasswordUtil.DEFAULT_OTP_LENGTH);
        } catch (final java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static long currentStep() {
        return System.currentTimeMillis() / 1000L / STEP;
    }

    private static void sleep(final long millis) {
        try {
            Thread.sleep(millis);
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
