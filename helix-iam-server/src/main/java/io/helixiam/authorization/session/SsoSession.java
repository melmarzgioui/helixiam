/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import java.time.Instant;
import java.util.List;

/**
 * Helix IAM SSO P4: one single sign-on session — a single browser login (keyed by the OIDC {@code sid})
 * spanning every client the user has authorized in it. The unit the Sessions admin lists and Single
 * Logout terminates.
 */
public record SsoSession(String ssoSessionId, String principalName, List<ClientInSession> clients,
                         Instant issuedAt, Instant expiresAt) {

    /** One client's authorization within an SSO session. */
    public record ClientInSession(String authorizationId, String clientId, String grantType, List<String> scopes,
                                  Instant issuedAt, Instant expiresAt) {
    }

    /** Every underlying OAuth2 authorization id in this session (for cascading revoke / logout). */
    public List<String> authorizationIds() {
        return clients.stream().map(ClientInSession::authorizationId).filter(java.util.Objects::nonNull).toList();
    }
}
