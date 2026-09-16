/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.federation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM E8.2: a (realm, alias) reference for fetch/delete of an identity-provider config.
 * Subscriber-side copy of the publisher's two-copy DTO.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record IdentityProviderRef(String realmId, String alias) {
}
