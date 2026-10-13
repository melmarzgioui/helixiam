/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.federation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

/**
 * Helix IAM E8.1: a per-realm identity-provider configuration as it crosses AMQP and the admin API.
 *
 * <p>The {@code protocol} is the family the broker registers under (oidc / saml / ldap / eid); the
 * {@code config} map carries the protocol-specific settings (issuer, clientId, ssoUrl, …) so the
 * store stays schema-stable as new provider types are added. Mirrors the publisher-side copy.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record IdentityProviderConfig(String realmId, String alias, String protocol, String displayName,
                                     boolean enabled, Map<String, String> config) {

    /**
     * The runtime {@code config} map holds the decrypted secrets ({@link
     * io.helixiam.authorization.federation.ProviderSecretKeys}); the generated record {@code toString} would print them,
     * so a secret's value is redacted here (any protocol's secret key, whatever this record's protocol).
     */
    @Override
    public String toString() {
        return "IdentityProviderConfig[realmId=" + realmId + ", alias=" + alias + ", protocol=" + protocol
                + ", displayName=" + displayName + ", enabled=" + enabled + ", config="
                + io.helixiam.authorization.federation.ProviderSecretKeys.redacted(protocol, config) + "]";
    }
}
