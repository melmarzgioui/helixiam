/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.notification.utils;

import java.security.SecureRandom;
import java.util.UUID;

/**
 * Vendored from io.helixiam.subscriber.starter.notification.utils.CodeGeneration.
 * Deviation: the original used org.apache.commons.lang3.RandomStringUtils.random(10, 0, 0,
 * true, false, null, new SecureRandom()) (letters-only, no digits, length 10). commons-lang3 is
 * not a helix-iam-server dependency, so generateSimpleCode() is reimplemented with a plain
 * SecureRandom draw over the same letters-only alphabet to preserve behaviour without adding a
 * new dependency. See VENDOR-MAP.md.
 */
public final class CodeGeneration {

    private static final String LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private static final int SIMPLE_CODE_LENGTH = 10;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private CodeGeneration() {
        throw new IllegalAccessError("Utility class");
    }

    public static String generateSimpleCode() {
        final StringBuilder builder = new StringBuilder(SIMPLE_CODE_LENGTH);
        for (int i = 0; i < SIMPLE_CODE_LENGTH; i++) {
            builder.append(LETTERS.charAt(SECURE_RANDOM.nextInt(LETTERS.length())));
        }
        return builder.toString();
    }

    public static String generateCode() {
        return UUID.randomUUID().toString();
    }
}
