/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.scim;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM B7: realm-scoped reference to one outbound SCIM target (delete by id within a realm). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ScimTargetRef(String realmId, String id) {
}
