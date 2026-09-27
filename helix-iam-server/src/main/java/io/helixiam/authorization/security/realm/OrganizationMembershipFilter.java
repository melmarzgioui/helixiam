/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.realm;

import io.helixiam.authorization.domain.org.Organization;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.service.org.OrganizationMembershipPolicy;
import io.helixiam.common.log.LogSafe;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import io.helixiam.authorization.security.mfa.domain.MfaAuthentication;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

/**
 * Item E4: on {@code /oauth2/authorize} with an {@code organization} hint, once the user has signed in (every factor
 * done: it runs after the two-step gate), refuse the request when the hinted organization requires membership and the
 * user is not a member. The client gets {@code error=access_denied} (with its {@code state}) at its redirect URI —
 * only a redirect URI registered for the client, else the request is left to the authorization endpoint, which
 * rejects it. Anonymous requests, and a sign-in still waiting for its second factor, pass (they are sent to the login
 * or code page first). The refusal is audited
 * ({@code ORGANIZATION_ACCESS_DENIED}).
 *
 * <p>Relying parties that need the guarantee should also check the {@code organizations} claim: a user can drop the
 * hint from the URL, and then there is nothing to enforce.
 */
public class OrganizationMembershipFilter extends OncePerRequestFilter {

    private static final Logger LOG = LogManager.getLogger(OrganizationMembershipFilter.class);
    private static final String PARAM = "organization";
    private static final String SPRING_SECURITY_CONTEXT_KEY = "SPRING_SECURITY_CONTEXT";

    private final OrganizationMembershipPolicy policy;
    private final RegisteredClientRepository clients;
    private final AuditLog audit;

    public OrganizationMembershipFilter(final OrganizationMembershipPolicy policy, final RegisteredClientRepository clients,
                                        final AuditLog audit) {
        this.policy = policy;
        this.clients = clients;
        this.audit = audit;
    }

    @Override
    protected boolean shouldNotFilter(final HttpServletRequest request) {
        return !"/oauth2/authorize".equals(request.getServletPath()) || request.getParameter(PARAM) == null;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
                                    final FilterChain chain) throws ServletException, IOException {
        final Authentication auth = currentAuthentication(request);
        if (auth == null || !auth.isAuthenticated() || auth instanceof MfaAuthentication
                || !(auth.getPrincipal() instanceof UserCredentials user)) {
            chain.doFilter(request, response);
            return;
        }
        final String realm = RealmContextHolder.get();
        final Optional<Organization> denied = policy.deniedOrganization(realm, request.getParameter(PARAM),
                user.getUsername()); // the principal's username is its user id
        if (denied.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }
        final String redirect = registeredRedirectUri(request);
        if (redirect == null) {
            chain.doFilter(request, response); // unknown client / redirect URI: the endpoint rejects it
            return;
        }
        LOG.info("Sign-in refused in realm {}: user {} is not a member of organization {} (membership required)",
                LogSafe.sanitize(realm), LogSafe.sanitize(user.getUsername()), LogSafe.sanitize(denied.get().getOrgId()));
        if (audit != null) {
            audit.emit(AuditEvent.authn(AuditContext.nowIso(), "ORGANIZATION_ACCESS_DENIED", realm, user.getUsername(),
                    AuditContext.clientIp(request), "FAILURE", Map.of("organization", denied.get().getOrgId(),
                            "client", String.valueOf(LogSafe.sanitize(request.getParameter("client_id"))))));
        }
        final UriComponentsBuilder target = UriComponentsBuilder.fromUriString(redirect)
                .queryParam("error", "access_denied")
                .queryParam("error_description", "Not a member of the organization");
        final String state = request.getParameter("state");
        if (state != null) {
            target.queryParam("state", state);
        }
        response.sendRedirect(target.encode().build().toUriString());
    }

    /**
     * The request's authentication: from {@link SecurityContextHolder} when populated, else from the persisted
     * {@code SPRING_SECURITY_CONTEXT} session attribute (the deferred context may not be resolved at this position, as
     * in {@code PromptAndMaxAgeAuthorizeFilter}).
     */
    private static Authentication currentAuthentication(final HttpServletRequest request) {
        final Authentication held = SecurityContextHolder.getContext().getAuthentication();
        if (held != null && held.isAuthenticated() && !(held instanceof AnonymousAuthenticationToken)) {
            return held;
        }
        final HttpSession session = request.getSession(false);
        if (session != null && session.getAttribute(SPRING_SECURITY_CONTEXT_KEY) instanceof SecurityContext ctx) {
            return ctx.getAuthentication();
        }
        return held;
    }

    /** The request's {@code redirect_uri} when registered for its client (or the client's only one); else null. */
    private String registeredRedirectUri(final HttpServletRequest request) {
        final String clientId = request.getParameter("client_id");
        final RegisteredClient client = clientId == null ? null : clients.findByClientId(clientId);
        if (client == null) {
            return null;
        }
        final String requested = request.getParameter("redirect_uri");
        if (requested == null) {
            return client.getRedirectUris().size() == 1 ? client.getRedirectUris().iterator().next() : null;
        }
        return client.getRedirectUris().contains(requested) ? requested : null;
    }
}
