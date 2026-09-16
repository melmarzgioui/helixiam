/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import java.time.Instant;
import java.util.List;

/**
 * Helix IAM E8.5-S4: an active session as the console shows it — the user/service principal, the
 * client they signed into, the grant type, scopes and lifetime. Backs the Sessions admin screen.
 */
public record SessionSummary(String id, String principalName, String clientId, String grantType,
                             List<String> scopes, Instant issuedAt, Instant expiresAt) {
}
