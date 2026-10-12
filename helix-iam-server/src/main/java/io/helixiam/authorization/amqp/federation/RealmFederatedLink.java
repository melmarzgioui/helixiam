/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.federation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Task 21a: request DTO — link (alias, external subject) to {@code userId} of {@code realmId} only if the subject is
 * free: not linked, or linked to an owner that no longer exists in the realm (a stale link, replaced atomically). An
 * existing live link is never overwritten. JSON-marshalled.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RealmFederatedLink(String realmId, String idpAlias, String externalSubject, String userId) {
}