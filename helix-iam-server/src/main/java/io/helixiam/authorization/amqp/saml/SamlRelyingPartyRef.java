/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.saml;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM: a (realm, entityId) reference for fetch/delete of a SAML relying party.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SamlRelyingPartyRef(String realmId, String entityId) {
}
