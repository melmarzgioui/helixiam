/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import io.helixiam.authorization.security.session.SsoSessionBindingAuthorizationService;
import io.helixiam.authorization.session.logout.BackchannelLogoutNotifier;
import io.helixiam.authorization.session.logout.LogoutTargetResolver;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.stereotype.Service;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Helix IAM SSO P5/P6: terminates a whole SSO session — removes every client authorization it spans (so no
 * refresh token survives) and ends that session's browser login (the HTTP session(s) recorded on its
 * authorizations; the user's other browser sessions are untouched). When a realm + issuer are supplied it also
 * fans out OIDC Back-Channel Logout {@code logout_token}s to the clients that registered a back-channel URI.
 * Returns the terminated {@link SsoSession} so callers (OIDC end_session, SAML SLO, the Sessions admin) can
 * additionally drive front-channel logout.
 */
@Service
public class SsoLogoutService {

    private static final Logger LOG = LogManager.getLogger(SsoLogoutService.class);

    private final SsoSessionStore sessionStore;
    private final OAuth2AuthorizationService authorizationService;
    private final SpringSessionStore springSessionStore;
    private final BackchannelLogoutNotifier backchannelNotifier;
    private final LogoutTargetResolver targetResolver;
    private final HttpSessionTerminator httpSessions;

    public SsoLogoutService(final SsoSessionStore sessionStore, final OAuth2AuthorizationService authorizationService,
                            final SpringSessionStore springSessionStore,
                            final BackchannelLogoutNotifier backchannelNotifier,
                            final LogoutTargetResolver targetResolver,
                            final HttpSessionTerminator httpSessions) {
        this.sessionStore = sessionStore;
        this.authorizationService = authorizationService;
        this.springSessionStore = springSessionStore;
        this.backchannelNotifier = backchannelNotifier;
        this.targetResolver = targetResolver;
        this.httpSessions = httpSessions;
    }

    /** Terminate the SSO session with this id (no logout fan-out); returns it or {@code null} if unknown. */
    public SsoSession terminate(final String ssoSessionId) {
        return terminate(ssoSessionId, null, null);
    }

    /**
     * Terminate the SSO session and, when {@code realm} + {@code issuerUrl} are supplied, fire OIDC
     * Back-Channel Logout to every participating client that registered a back-channel URI (best-effort).
     */
    public SsoSession terminate(final String ssoSessionId, final String realm, final String issuerUrl) {
        final SsoSession session = sessionStore.findById(ssoSessionId);
        if (session == null) {
            return null;
        }
        boolean sidBound = false;
        final Set<String> browserSessions = new LinkedHashSet<>();
        for (final String authorizationId : session.authorizationIds()) {
            final OAuth2Authorization authorization = authorizationService.findById(authorizationId);
            if (authorization != null) {
                sidBound |= authorization.getAttribute(SsoSessionBindingAuthorizationService.SID_ATTRIBUTE) != null;
                final Object httpSession = authorization.getAttribute(SsoSessionBindingAuthorizationService.HTTP_SESSION_ATTRIBUTE);
                if (httpSession instanceof String id && !id.isBlank()) {
                    browserSessions.add(id);
                }
                authorizationService.remove(authorization);
            }
        }
        if (sidBound) {
            // End only this SSO session's browser login(s); the user's other browsers stay signed in.
            httpSessions.deleteAll(browserSessions);
        } else if (session.principalName() != null) {
            // Legacy session without a sid (authorizations from before sids): the old by-user behaviour.
            springSessionStore.deleteByPrincipal(session.principalName());
        }
        LOG.info("Terminated SSO session {} ({} client authorizations)",
                LogSafe.sanitize(ssoSessionId), session.clients().size());

        if (realm != null && issuerUrl != null) {
            fireBackchannel(session, realm, issuerUrl);
        }
        return session;
    }

    private void fireBackchannel(final SsoSession session, final String realm, final String issuerUrl) {
        try {
            final List<String> clientIds = session.clients().stream()
                    .map(SsoSession.ClientInSession::clientId).toList();
            final List<BackchannelLogoutNotifier.Target> targets = targetResolver.backchannelTargets(realm, clientIds);
            backchannelNotifier.notifyClients(realm, issuerUrl, session.principalName(), session.ssoSessionId(),
                    targets);
        } catch (final RuntimeException e) {
            LOG.warn("Back-channel logout fan-out failed for SSO session {} (logout already completed): {}",
                    session.ssoSessionId(), e.getMessage());
        }
    }
}
