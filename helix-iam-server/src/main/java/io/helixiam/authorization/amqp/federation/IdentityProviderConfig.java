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
}
