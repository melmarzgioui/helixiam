/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.federation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM E8.2: a (realm, alias) reference for fetch/delete of an identity-provider config.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record IdentityProviderRef(String realmId, String alias) {
}
