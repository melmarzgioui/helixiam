/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.agent;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM Agent (NHI): publisher-side copy of the subscriber's agent DTO (two-copy, SAME field order for
 * Jackson-over-AMQP). The registry record is non-secret, so every field crosses the seam and reaches the
 * console unmasked. Timestamps are epoch-millis {@code Long}s. {@code clientId} is the bound OIDC client an
 * agent uses for token issuance (nullable).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AgentIdentityDto(String id, String realmId, String name, String displayName, String description,
                               String owner, String status, String authMethod, String clientId, String scopes,
                               boolean enabled, Long createdAt, Long expiresAt, Long lastUsedAt, String roles) {
}
