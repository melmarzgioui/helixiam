/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import io.helixiam.authorization.amqp.client.ClientAdminPublisher;
import io.helixiam.authorization.amqp.client.ClientDto;
import io.helixiam.authorization.session.logout.BackchannelLogoutNotifier;
import io.helixiam.authorization.session.logout.LogoutTargetResolver;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Open issue E7: ends every session of one user of a realm in one call.
 *
 * <ol>
 *   <li>The user's browser (HTTP) sessions are deleted first, so a signed-in browser cannot start a new
 *       authorization meanwhile.</li>
 *   <li>Every SSO session of the user that has a client in the realm is terminated through
 *       {@link SsoLogoutService#terminate(String, String, String)}: its authorizations are removed and every client of
 *       it that registered a back-channel URI gets a realm-signed, {@code sid}-based, short-lived logout token.</li>
 *   <li>Every remaining OAuth2 authorization of the user at a client of the realm (for example one that was never
 *       part of an SSO session) is removed, which also kills its refresh token. Each such client with a back-channel
 *       URI gets one logout token with {@code sub} only (no session to name), which OIDC Back-Channel Logout 1.0
 *       defines as "every session of this user at the RP".</li>
 * </ol>
 *
 * The caller has already checked that the user belongs to the realm; everything here is scoped to the realm's
 * clients as well, so another realm's authorizations are never touched.
 */
@Service
public class UserSessionRevoker {

    private static final Logger LOG = LogManager.getLogger(UserSessionRevoker.class);

    private final SsoSessionStore ssoSessions;
    private final SessionStore authorizations;
    private final OAuth2AuthorizationService authorizationService;
    private final SsoLogoutService ssoLogout;
    private final SpringSessionStore browserSessions;
    private final BackchannelLogoutNotifier backchannel;
    private final LogoutTargetResolver targets;
    private final ClientAdminPublisher clients;
    private final String idpBaseUrl;

    public UserSessionRevoker(final SsoSessionStore ssoSessions, final SessionStore authorizations,
                              final OAuth2AuthorizationService authorizationService, final SsoLogoutService ssoLogout,
                              final SpringSessionStore browserSessions, final BackchannelLogoutNotifier backchannel,
                              final LogoutTargetResolver targets, final ClientAdminPublisher clients,
                              @Value("${idp.base.url}") final String idpBaseUrl) {
        this.ssoSessions = ssoSessions;
        this.authorizations = authorizations;
        this.authorizationService = authorizationService;
        this.ssoLogout = ssoLogout;
        this.browserSessions = browserSessions;
        this.backchannel = backchannel;
        this.targets = targets;
        this.clients = clients;
        this.idpBaseUrl = idpBaseUrl;
    }

    /**
     * What was ended.
     *
     * @param ssoSessions      SSO sessions terminated (each with back-channel logout to its clients)
     * @param authorizations   OAuth2 authorizations removed (access and refresh tokens), in and outside SSO sessions
     * @param browserSessions  HTTP sessions deleted (0 when the store cannot count them)
     */
    public record Result(int ssoSessions, int authorizations, int browserSessions) {
    }

    /** Ends every session of {@code userId} (the principal name) at the clients of {@code realmId}. */
    public Result revokeAll(final String realmId, final String userId) {
        final Set<String> realmClients = clients.list(realmId).stream().map(ClientDto::id)
                .filter(Objects::nonNull).collect(Collectors.toSet());
        final String issuer = idpBaseUrl + "/realms/" + realmId;
        // Browser sessions first, so a signed-in browser cannot start a new authorization while the rest is revoked.
        final int browser = browserSessions.deleteByPrincipal(userId);

        int sessions = 0;
        int removed = 0;
        for (final SsoSession s : ssoSessions.findAll()) {
            if (!userId.equals(s.principalName())
                    || s.clients().stream().noneMatch(c -> realmClients.contains(c.clientId()))) {
                continue;
            }
            final SsoSession ended = ssoLogout.terminate(s.ssoSessionId(), realmId, issuer);
            if (ended != null) {
                sessions++;
                removed += ended.authorizationIds().size();
            }
        }

        // Authorizations outside any SSO session (or left behind): remove them and tell their clients by sub.
        final Set<String> orphanClients = new LinkedHashSet<>();
        for (final SessionRow row : authorizations.findAll()) {
            if (!userId.equals(row.principalName()) || !realmClients.contains(row.registeredClientId())) {
                continue;
            }
            final OAuth2Authorization authorization = authorizationService.findById(row.id());
            if (authorization != null) {
                authorizationService.remove(authorization);
                removed++;
                orphanClients.add(row.registeredClientId());
            }
        }
        if (!orphanClients.isEmpty()) {
            try {
                backchannel.notifyClients(realmId, issuer, userId, null,
                        targets.backchannelTargets(realmId, new ArrayList<>(orphanClients)));
            } catch (final RuntimeException e) {
                LOG.warn("Back-channel logout fan-out failed for user {} in realm {} (tokens already revoked): {}",
                        LogSafe.sanitize(userId), LogSafe.sanitize(realmId), LogSafe.sanitize(e.getMessage()));
            }
        }

        LOG.info("Admin revoked every session of user {} in realm {}: {} SSO sessions, {} authorizations, "
                        + "{} browser sessions", LogSafe.sanitize(userId), LogSafe.sanitize(realmId), sessions, removed,
                browser);
        return new Result(sessions, removed, browser);
    }
}
