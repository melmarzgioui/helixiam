/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.federation;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Both copies of the identity-provider config DTO carry the merged runtime config, decrypted secrets included; their
 * {@code toString} must never print a secret, so a future log line of one cannot leak it.
 */
class IdentityProviderConfigToStringTest {

    private static final Map<String, String> CONFIG = Map.of(
            "issuer", "https://idp.example",
            "clientSecret", "s3cr3t-client",
            "spSigningPrivateKey", "-----BEGIN PRIVATE KEY-----MIIE",
            "bindPassword", "s3cr3t-bind",
            "subjectPepper", "s3cr3t-pepper");

    @Test
    void theDomainCopy_redactsEverySecret_andKeepsTheRest() {
        final String text = new IdentityProviderConfig("gov", "corp", "oidc", "Corp", true, CONFIG).toString();

        assertThat(text).doesNotContain("s3cr3t").doesNotContain("MIIE")
                .contains("clientSecret").contains("https://idp.example").contains("corp").contains("gov");
    }

    @Test
    void thePublisherCopy_redactsEverySecret() {
        final String text = new io.helixiam.authorization.amqp.federation.IdentityProviderConfig(
                "gov", "corp", "eid", "Corp", true, CONFIG).toString();

        assertThat(text).doesNotContain("s3cr3t").doesNotContain("MIIE").contains("https://idp.example");
    }

    @Test
    void aNullConfig_printsAsNull() {
        assertThat(new IdentityProviderConfig("gov", "corp", "oidc", "Corp", true, null).toString()).contains("config=null");
    }
}
