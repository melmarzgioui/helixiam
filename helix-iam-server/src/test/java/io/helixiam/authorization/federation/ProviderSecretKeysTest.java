/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Task 4 (security): which identity-provider config keys are secrets, per protocol. Secrets are stored encrypted in
 * {@code identity_provider.secret_json} and never returned by the admin API.
 */
class ProviderSecretKeysTest {

    @ParameterizedTest
    @CsvSource({
            "oidc,clientSecret", "social,clientSecret", "OIDC,clientSecret",
            "eid,spDecryptionPrivateKey", "eid,spSigningPrivateKey",
            "digid,spDecryptionPrivateKey", "eherkenning,spSigningPrivateKey", "eidas,spDecryptionPrivateKey",
            "eudi-wallet,accessCertificatePrivateKey", "eudi-wallet,subjectPepper",
            "openid4vp,accessCertificatePrivateKey", "Wallet,subjectPepper",
            "ldap,bindPassword", "ldap,bindPw", "ad,bindCredential"})
    void secretKeys_perProtocol(final String protocol, final String key) {
        assertThat(ProviderSecretKeys.isSecret(protocol, key)).isTrue();
        assertThat(ProviderSecretKeys.keysFor(protocol)).contains(key);
    }

    @ParameterizedTest
    @CsvSource({
            "oidc,clientId", "oidc,issuer", "eid,idpSigningCertificate", "eid,spSigningCertificate",
            "saml,idpSigningCertificate", "eudi-wallet,accessCertificate", "ldap,bindDn", "oidc,clientSecretSet"})
    void publicSettings_areNotSecret(final String protocol, final String key) {
        assertThat(ProviderSecretKeys.isSecret(protocol, key)).isFalse();
    }

    @Test
    void aKnownSecretKey_isSecretUnderAnyProtocol() {
        // Defence in depth: an eID key stored under "oidc" (or an unknown protocol) is still never kept in clear.
        assertThat(ProviderSecretKeys.isSecret("oidc", "spSigningPrivateKey")).isTrue();
        assertThat(ProviderSecretKeys.isSecret("saml", "clientSecret")).isTrue();
        assertThat(ProviderSecretKeys.isSecret(null, "subjectPepper")).isTrue();
        assertThat(ProviderSecretKeys.isSecret("oidc", null)).isFalse();
    }

    @Test
    void keysFor_unknownProtocol_isEmpty_andSamlHasNone() {
        assertThat(ProviderSecretKeys.keysFor("saml")).isEmpty();
        assertThat(ProviderSecretKeys.keysFor(null)).isEmpty();
        assertThat(ProviderSecretKeys.keysFor("nope")).isEmpty();
    }

    @Test
    void flagNames() {
        assertThat(ProviderSecretKeys.setFlag("clientSecret")).isEqualTo("clientSecretSet");
        assertThat(ProviderSecretKeys.clearFlag("clientSecret")).isEqualTo("clearClientSecret");
        assertThat(ProviderSecretKeys.clearFlag("spSigningPrivateKey")).isEqualTo("clearSpSigningPrivateKey");
        assertThat(ProviderSecretKeys.isControlKey("clientSecretSet")).isTrue();
        assertThat(ProviderSecretKeys.isControlKey("clearSpDecryptionPrivateKey")).isTrue();
        assertThat(ProviderSecretKeys.isControlKey("clientId")).isFalse();
        assertThat(ProviderSecretKeys.isControlKey("clientSecret")).isFalse();
    }

    @Test
    void split_movesSecretsOut_andDropsControlKeys() {
        final Map<String, String> config = new LinkedHashMap<>();
        config.put("clientId", "web");
        config.put("clientSecret", "s3cret");
        config.put("clientSecretSet", "true");
        config.put("clearClientSecret", "false");

        final ProviderSecretKeys.Split split = ProviderSecretKeys.split("oidc", config);

        assertThat(split.plain()).containsExactly(Map.entry("clientId", "web"));
        assertThat(split.secrets()).containsExactly(Map.entry("clientSecret", "s3cret"));
    }
}
