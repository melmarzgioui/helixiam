/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.saml;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM: a per-realm SAML2 relying party (SP) as it crosses AMQP and the admin API. Subscriber-side
 * copy of the publisher's two-copy DTO. Mirrors the federation {@code IdentityProviderConfig}.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SamlRelyingPartyConfig(String realmId, String entityId, String assertionConsumerServiceUrl,
                                     String defaultAuthnContextClassRef, String singleLogoutServiceUrl,
                                     String signingCertificate, boolean enabled, String applicationId,
                                     SamlSpOptions options) {
}
