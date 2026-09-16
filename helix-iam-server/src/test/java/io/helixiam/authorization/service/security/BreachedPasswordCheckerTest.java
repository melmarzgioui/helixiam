/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.security;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Auth-hardening (feature 4): k-anonymity breached-password check with a stubbed HIBP range fetcher.
 * SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8 → prefix 5BAA6, suffix 1E4C9B93F3F0682250B6CF8331B7EE68FD8.
 */
class BreachedPasswordCheckerTest {

    private static final String PWNED_SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    @Test
    void detectsBreach_whenSuffixPresentInRange() {
        final BreachedPasswordChecker checker = new BreachedPasswordChecker(
                prefix -> {
                    assertThat(prefix).isEqualTo("5BAA6");
                    return PWNED_SUFFIX + ":42\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1";
                });
        assertThat(checker.isBreached("password")).isTrue();
    }

    @Test
    void notBreached_whenSuffixAbsent() {
        final BreachedPasswordChecker checker = new BreachedPasswordChecker(
                prefix -> "0000000000000000000000000000000000A:3\r\n1111111111111111111111111111111111B:1");
        assertThat(checker.isBreached("password")).isFalse();
    }

    @Test
    void suffixMatchIsCaseInsensitive() {
        final BreachedPasswordChecker checker = new BreachedPasswordChecker(prefix -> PWNED_SUFFIX.toLowerCase() + ":7");
        assertThat(checker.isBreached("password")).isTrue();
    }

    @Test
    void failsOpen_onFetchError() {
        final BreachedPasswordChecker checker = new BreachedPasswordChecker(prefix -> {
            throw new RuntimeException("HIBP down");
        });
        assertThat(checker.isBreached("password")).isFalse();
    }

    @Test
    void failsOpen_onEmptyOrNullBody() {
        assertThat(new BreachedPasswordChecker(prefix -> null).isBreached("password")).isFalse();
        assertThat(new BreachedPasswordChecker(prefix -> "   ").isBreached("password")).isFalse();
    }

    @Test
    void emptyPassword_isNeverBreached() {
        final BreachedPasswordChecker checker = new BreachedPasswordChecker(prefix -> PWNED_SUFFIX);
        assertThat(checker.isBreached("")).isFalse();
        assertThat(checker.isBreached(null)).isFalse();
    }
}
