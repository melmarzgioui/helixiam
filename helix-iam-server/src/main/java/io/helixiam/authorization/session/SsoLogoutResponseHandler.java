/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import io.helixiam.authorization.session.logout.FrontchannelLogoutRenderer;
import io.helixiam.authorization.session.logout.LogoutTargetResolver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Helix IAM SSO P5/P6: the OIDC end_session success handler. SAS has already validated the {@code id_token_hint}
 * and {@code post_logout_redirect_uri}; this cascades the logout — terminating the whole SSO session (removing
 * the user's client authorizations + HTTP session and firing back-channel {@code logout_token}s via
 * {@link SsoLogoutService}). If any participating client registered a front-channel logout URL, an iframe
 * interstitial drives those before the final redirect; otherwise it redirects straight to the post-logout URI.
 */
@Component
public class SsoLogoutResponseHandler implements AuthenticationSuccessHandler {

    private static final Logger LOG = LogManager.getLogger(SsoLogoutResponseHandler.class);

    private final SsoLogoutService ssoLogoutService;
    private final LogoutTargetResolver targetResolver;
    private final FrontchannelLogoutRenderer frontchannelRenderer;
    private final io.helixiam.authorization.federation.FederatedLogoutCoordinator federatedLogoutCoordinator;

    public SsoLogoutResponseHandler(final SsoLogoutService ssoLogoutService, final LogoutTargetResolver targetResolver,
                                    final FrontchannelLogoutRenderer frontchannelRenderer,
                                    final io.helixiam.authorization.federation.FederatedLogoutCoordinator federatedLogoutCoordinator) {
        this.ssoLogoutService = ssoLogoutService;
        this.targetResolver = targetResolver;
        this.frontchannelRenderer = frontchannelRenderer;
        this.federatedLogoutCoordinator = federatedLogoutCoordinator;
    }

    @Override
    public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response,
                                        final Authentication authentication) throws IOException {
        String postLogoutRedirectUri = null;
        String state = null;
        String issuerUrl = null;
        String realm = null;
        SsoSession terminated = null;
        if (authentication instanceof OidcLogoutAuthenticationToken token) {
            postLogoutRedirectUri = token.getPostLogoutRedirectUri();
            state = token.getState();
            // The SSO-session key == oauth2_authorization.principal_name == the id_token `sub` (the userId),
            // which is NOT the session's display principal. Terminate by the sub so the cascade matches.
            final String subject = token.getIdToken() != null ? token.getIdToken().getSubject()
                    : (token.getPrincipal() instanceof Authentication p ? p.getName() : null);
            if (subject != null) {
                // The logout_token `iss` MUST equal the issuer the RP validated its id_token against — read it
                // straight off the id_token so a back-channel logout_token is accepted by every RP. The realm
                // (for resolving each client's back-/front-channel URI) comes from the in-flight request context.
                issuerUrl = token.getIdToken() != null && token.getIdToken().getIssuer() != null
                        ? token.getIdToken().getIssuer().toString() : null;
                realm = io.helixiam.authorization.security.realm.RealmContextHolder.get();
                terminated = ssoLogoutService.terminate(subject, realm, issuerUrl);
                if (terminated != null) {
                    LOG.info("OIDC end_session terminated SSO session for {} (realm {})", subject, realm);
                }
            }
        }

        final String redirectTarget = withState(postLogoutRedirectUri, state);

        final HttpSession session = request.getSession(false);
        // SSO P9: if this browser session was brokered through an upstream IdP, propagate the logout there
        // (OIDC end_session / SAML SLO) before we drop the local session. Best-effort — never blocks.
        if (session != null) {
            final Object idpAlias = session.getAttribute(
                    io.helixiam.authorization.security.flow.FederationBrokerController.IDP_SOURCE_ATTR);
            if (idpAlias instanceof String alias && !alias.isBlank()) {
                final Object idpSubject = session.getAttribute(
                        io.helixiam.authorization.security.flow.FederationBrokerController.IDP_SUBJECT_ATTR);
                federatedLogoutCoordinator.propagate(new io.helixiam.authorization.federation.spi.IdentityProvider
                        .LogoutContext(realm, idpSubject instanceof String s ? s : null, alias, null,
                        idpSubject instanceof String s2 ? s2 : null, null));
            }
            session.invalidate();
        }
        SecurityContextHolder.clearContext();

        // OIDC Front-Channel Logout: if any client in the session registered a front-channel URL, serve an
        // iframe interstitial (one iframe per client) that then redirects; else redirect immediately.
        final List<LogoutTargetResolver.FrontchannelTarget> frontchannel = terminated != null && realm != null
                ? targetResolver.frontchannelTargets(realm, terminated.clients().stream()
                .map(SsoSession.ClientInSession::clientId).toList())
                : List.of();
        if (!frontchannel.isEmpty()) {
            final String sid = terminated != null ? terminated.ssoSessionId() : null;
            final String html = frontchannelRenderer.render(issuerUrl, sid, frontchannel, redirectTarget);
            response.setContentType("text/html;charset=UTF-8");
            response.setHeader("Cache-Control", "no-store");
            response.getWriter().write(html);
            return;
        }

        response.sendRedirect(redirectTarget);
    }

    private static String withState(final String postLogoutRedirectUri, final String state) {
        if (postLogoutRedirectUri == null || postLogoutRedirectUri.isBlank()) {
            return "/";
        }
        if (state == null || state.isBlank()) {
            return postLogoutRedirectUri;
        }
        final String sep = postLogoutRedirectUri.contains("?") ? "&" : "?";
        return postLogoutRedirectUri + sep + "state=" + URLEncoder.encode(state, StandardCharsets.UTF_8);
    }
}
