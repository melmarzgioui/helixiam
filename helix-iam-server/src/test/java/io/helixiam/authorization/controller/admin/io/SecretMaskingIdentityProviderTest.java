/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin.io;

import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Task 4 (security): the realm export masks every identity-provider secret named by {@code ProviderSecretKeys}, also
 * the ones the key-name heuristic misses (wallet {@code subjectPepper}, LDAP {@code bindPw}).
 */
class SecretMaskingIdentityProviderTest {

    private static final IdentityProviderConfig WALLET = new IdentityProviderConfig("gov", "wallet", "eudi-wallet",
            "Wallet", true, Map.of("subjectPepper", "pepper", "accessCertificatePrivateKey", "PEM", "clientId", "x"));
    private static final IdentityProviderConfig LDAP = new IdentityProviderConfig("gov", "ad", "ldap", "AD", true,
            Map.of("bindPw", "pw", "bindDn", "cn=admin"));

    @Test
    void mask_dropsProviderSecretKeys() {
        assertThat(SecretMasking.mask(WALLET).config()).containsOnlyKeys("clientId");
        assertThat(SecretMasking.mask(LDAP).config()).containsOnlyKeys("bindDn");
    }

    @Test
    void maskToPlaceholders_replacesProviderSecretKeys() {
        final Set<String> env = new HashSet<>();
        final Map<String, String> config = SecretMasking.maskToPlaceholders(WALLET, env).config();
        assertThat(config.get("subjectPepper")).startsWith("${").isNotEqualTo("pepper");
        assertThat(config.get("accessCertificatePrivateKey")).startsWith("${");
        assertThat(config).containsEntry("clientId", "x");
        assertThat(SecretMasking.maskToPlaceholders(LDAP, env).config().get("bindPw")).startsWith("${");
        assertThat(env).hasSize(3);
    }
}
