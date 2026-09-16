/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.user;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5: identifies one factor to revoke for a realm user (publisher-side copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CredentialRevokeRef(String realmId, String userId, String type, String id) {
}
