/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.federation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

/**
 * Helix IAM E8.2: publisher-side copy of a per-realm identity-provider config (two-copy DTO; mirrors
 * the subscriber's {@code domain.federation.IdentityProviderConfig}). Carried over AMQP between the
 * admin API and the identity-domain store.
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
