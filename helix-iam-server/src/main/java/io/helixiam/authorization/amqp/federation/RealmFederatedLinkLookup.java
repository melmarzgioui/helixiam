/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.federation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Task 21a: request DTO — the user of {@code realmId} linked to (alias, external subject), if any. A link whose owner no
 * longer exists in the realm (deleted, or belonging to another realm) counts as absent. JSON-marshalled.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RealmFederatedLinkLookup(String realmId, String idpAlias, String externalSubject) {
}