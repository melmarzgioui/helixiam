/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

/**
 * A realm's signing keys changed (import, CSR, certificate attached, activate, rotate, retire): the JWKS and SAML
 * credential caches of this replica drop the realm's entry. Other replicas pick the change up within their cache TTL.
 */
public record RealmKeysChangedEvent(String realmId) {
}
