/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM notifications (N6a): user-claim passthrough. Every claim of the bound user is exposed to a message
 * template under a {@code user.} namespace (e.g. {@code {{user.email}}}, {@code {{user.given_name}}}) so a
 * realm can personalise OTP / magic-link / push messages, without a custom claim ever clobbering a system
 * variable ({@code realm}/{@code code}/{@code ttl}/...).
 */
class MessageVariablesTest {

    @Test
    void namespacesEachUserClaimUnderUserDot() {
        final Map<String, String> profile = new LinkedHashMap<>();
        profile.put("email", "ada@example.com");
        profile.put("given_name", "Ada");

        final Map<String, String> vars = MessageVariables.withUserClaims(Map.of("realm", "master"), profile);

        assertThat(vars).containsEntry("user.email", "ada@example.com")
                .containsEntry("user.given_name", "Ada")
                .containsEntry("realm", "master");
    }

    @Test
    void skipsNullOrBlankClaimKeysAndNullValues() {
        final Map<String, String> profile = new LinkedHashMap<>();
        profile.put("email", "ada@example.com");
        profile.put("phone_number", null);
        profile.put("", "ignored");

        final Map<String, String> vars = MessageVariables.withUserClaims(Map.of(), profile);

        assertThat(vars).containsOnlyKeys("user.email");
    }

    @Test
    void systemVariablesWinOnCollision() {
        // A user with a custom claim literally named "code" must NOT override the OTP code (which lives as a
        // bare system var). The claim is still available namespaced as user.code.
        final Map<String, String> profile = Map.of("code", "claim-value");

        final Map<String, String> vars = MessageVariables.withUserClaims(Map.of("code", "123456"), profile);

        assertThat(vars).containsEntry("code", "123456").containsEntry("user.code", "claim-value");
    }

    @Test
    void nullProfileYieldsBaseVarsOnly() {
        assertThat(MessageVariables.withUserClaims(Map.of("realm", "master"), null))
                .containsExactlyEntriesOf(Map.of("realm", "master"));
    }
}
