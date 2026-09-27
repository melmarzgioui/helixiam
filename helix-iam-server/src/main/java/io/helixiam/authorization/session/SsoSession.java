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
                         Instant issuedAt, Instant expiresAt, List<String> allAuthorizationIds) {

    /** A session whose authorizations are exactly the ones listed per client. */
    public SsoSession(final String ssoSessionId, final String principalName, final List<ClientInSession> clients,
                      final Instant issuedAt, final Instant expiresAt) {
        this(ssoSessionId, principalName, clients, issuedAt, expiresAt, null);
    }

    /** One client's authorization within an SSO session. */
    public record ClientInSession(String authorizationId, String clientId, String grantType, List<String> scopes,
                                  Instant issuedAt, Instant expiresAt) {
    }

    /**
     * Every underlying OAuth2 authorization id in this session (for cascading revoke / logout) — including older
     * authorizations of a client that signed in more than once in the session (e.g. after {@code prompt=login}),
     * which {@link #clients()} collapses to the newest one.
     */
    public List<String> authorizationIds() {
        if (allAuthorizationIds != null) {
            return allAuthorizationIds;
        }
        return clients.stream().map(ClientInSession::authorizationId).filter(java.util.Objects::nonNull).toList();
    }
}
