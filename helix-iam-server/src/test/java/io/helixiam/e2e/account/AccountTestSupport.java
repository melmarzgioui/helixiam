/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.account;

import io.helixiam.authorization.service.mfa.TotpService;
import io.helixiam.e2e.browser.TotpDevice;
import org.springframework.context.ApplicationContext;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** B1 tests: sets up an authenticator app for a user without a browser, and hands out its codes. */
final class AccountTestSupport {

    private static final Map<String, String> SECRETS = new ConcurrentHashMap<>();

    private AccountTestSupport() {
    }

    /** Enrols a fresh TOTP secret for {@code userId} (confirmed with the previous time step's code). */
    static void enrolTotp(final ApplicationContext context, final String userId) {
        final TotpService totp = context.getBean(TotpService.class);
        final String secret = totp.newSecret();
        if (!totp.confirmEnrolment(userId, secret, TotpDevice.codeAt(secret, step() - 1))) {
            throw new AssertionError("could not enrol TOTP for " + userId);
        }
        SECRETS.put(userId, secret);
    }

    /** The code of the user's authenticator for the current time step. */
    static String currentCode(final ApplicationContext context, final String userId) {
        return TotpDevice.codeAt(SECRETS.get(userId), step());
    }

    private static long step() {
        return System.currentTimeMillis() / 1000L / 30;
    }
}
