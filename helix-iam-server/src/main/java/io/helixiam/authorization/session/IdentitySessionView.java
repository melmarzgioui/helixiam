/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import java.time.Instant;
import java.util.List;

/** Unified admin projection of an active identity — an SSO session (user/agent) or a service-account token. */
public record IdentitySessionView(String id, IdentityType identityType, String principalName, String displayName,
                                  String realm, Instant issuedAt, Instant expiresAt, String revokeMode,
                                  List<ClientView> clients) {
  public record ClientView(String clientId, String grantType, List<String> scopes, Instant issuedAt, Instant expiresAt) {}
}
