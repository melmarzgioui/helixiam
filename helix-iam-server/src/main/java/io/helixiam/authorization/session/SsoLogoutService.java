package io.helixiam.authorization.session;

import io.helixiam.authorization.session.logout.BackchannelLogoutNotifier;
import io.helixiam.authorization.session.logout.LogoutTargetResolver;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Helix IAM SSO P5/P6: terminates a whole SSO session — removes every client authorization it spans (so no
 * refresh token survives) and deletes the user's HTTP session(s). When a realm + issuer are supplied it also
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

    public SsoLogoutService(final SsoSessionStore sessionStore, final OAuth2AuthorizationService authorizationService,
                            final SpringSessionStore springSessionStore,
                            final BackchannelLogoutNotifier backchannelNotifier,
                            final LogoutTargetResolver targetResolver) {
        this.sessionStore = sessionStore;
        this.authorizationService = authorizationService;
        this.springSessionStore = springSessionStore;
        this.backchannelNotifier = backchannelNotifier;
        this.targetResolver = targetResolver;
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
        for (final String authorizationId : session.authorizationIds()) {
            final OAuth2Authorization authorization = authorizationService.findById(authorizationId);
            if (authorization != null) {
                authorizationService.remove(authorization);
            }
        }
        if (session.principalName() != null) {
            springSessionStore.deleteByPrincipal(session.principalName());
        }
        LOG.info("Terminated SSO session {} ({} client authorizations)", ssoSessionId, session.clients().size());

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
            backchannelNotifier.notifyClients(issuerUrl, session.principalName(), session.ssoSessionId(), targets);
        } catch (final RuntimeException e) {
            LOG.warn("Back-channel logout fan-out failed for SSO session {} (logout already completed): {}",
                    session.ssoSessionId(), e.getMessage());
        }
    }
}
