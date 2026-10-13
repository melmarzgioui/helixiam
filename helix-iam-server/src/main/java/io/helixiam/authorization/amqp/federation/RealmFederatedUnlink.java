/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.federation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Task 21a: request DTO — remove every link {@code userId} of {@code realmId} has for {@code idpAlias}. JSON-marshalled.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RealmFederatedUnlink(String realmId, String userId, String idpAlias) {
}