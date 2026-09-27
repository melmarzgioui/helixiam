/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.account;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

/** The plausibility check on a new email address, and CodeQL #254 (java/polynomial-redos). */
class EmailChangeServiceNormaliseTest {

    @Test
    void plausibleAddresses_areTrimmedAndLowerCased() {
        assertThat(EmailChangeService.normalise("  Ada@Example.COM ")).isEqualTo("ada@example.com");
        assertThat(EmailChangeService.normalise("a.b+c@sub.example.co.uk")).isEqualTo("a.b+c@sub.example.co.uk");
        assertThat(EmailChangeService.normalise("a@b.c")).isEqualTo("a@b.c");
        assertThat(EmailChangeService.normalise("a@...")).isEqualTo("a@...");
        assertThat(EmailChangeService.normalise("a@b..")).isEqualTo("a@b..");
    }

    @Test
    void implausibleAddresses_areRefused() {
        for (final String bad : new String[]{null, "", "   ", "ada", "@example.com", "ada@", "ada@example",
                "ada@.com", "ada@example.", "ada@@example.com", "a@b@c.d", "ada smith@example.com",
                "ada@exa\tmple.com", "ada@example.com\nx", "ada@exa\u000Bmple.com", "a@.", "a@b.", "a@.."}) {
            assertThat(EmailChangeService.normalise(bad)).as(String.valueOf(bad)).isNull();
        }
        assertThat(EmailChangeService.normalise("a".repeat(250) + "@b.cd")).as("over 254 characters").isNull();
    }

    @Test
    void aPathologicalAddress_isCheckedInLinearTime() {
        // The shape CodeQL reported: "!@!." followed by many "!." and no valid end.
        final String longest = "!@!." + "!.".repeat(125) + "@";
        final String huge = "!@!." + "!.".repeat(500_000) + "@";
        assertTimeoutPreemptively(Duration.ofSeconds(1), () -> {
            assertThat(EmailChangeService.normalise(longest)).isNull();
            assertThat(EmailChangeService.normalise(huge)).isNull();
            assertThat(EmailChangeService.isPlausible(huge.substring(0, huge.length() - 1))).isTrue();
            assertThat(EmailChangeService.isPlausible(huge)).isFalse();
        });
    }
}
