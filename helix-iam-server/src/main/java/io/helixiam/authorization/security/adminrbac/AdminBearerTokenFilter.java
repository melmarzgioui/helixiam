/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.adminrbac;

import io.helixiam.authorization.amqp.clientrole.ClientRolePublisher;
import io.helixiam.authorization.amqp.clientrole.ServiceAccountRoleDto;
import io.helixiam.authorization.support.RealmScopedKey;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * 1.0 item 4: bearer-token access to {@code /admin/**} for service accounts (automation, CI, Terraform).
 *
 * <p>An {@code Authorization: Bearer} access token is accepted only if this server issued it, it is still
 * active (not expired, not revoked — it is resolved through the authorization store, not just signature
 * checked) and it came from the {@code client_credentials} grant. The service account's realm is the realm of
 * the token's issuer; its REALM roles are resolved live (a removed role takes effect immediately) and
 * presented as the same tenant-qualified authorities ({@code <role>_<realm>}) a console session carries, so
 * {@link AdminAuthorizationManager} applies unchanged: a service account holding {@code admin} is an admin of
 * its own realm only. The authentication lives for the request only (no session is created). Any other
 * bearer token is a 401. Requests without a bearer header are left to the session login and its CSRF check.
 */
public class AdminBearerTokenFilter extends OncePerRequestFilter {

    private static final Logger LOG = LogManager.getLogger(AdminBearerTokenFilter.class);
    private static final String BEARER = "Bearer ";

    private final OAuth2AuthorizationService authorizations;
    private final ClientRolePublisher clientRoles;

    public AdminBearerTokenFilter(final OAuth2AuthorizationService authorizations, final ClientRolePublisher clientRoles) {
        this.authorizations = authorizations;
        this.clientRoles = clientRoles;
    }

    /** True for an {@code /admin/**} request carrying a bearer token (these skip the session CSRF check). */
    public static boolean isAdminBearerRequest(final HttpServletRequest request) {
        return isAdminPath(request) && bearerToken(request) != null;
    }

    @Override
    protected boolean shouldNotFilter(final HttpServletRequest request) {
        return !isAdminBearerRequest(request);
    }

    /** The container's error dispatch (e.g. a 403 rendered via /error) must see the same authentication. */
    @Override
    protected boolean shouldNotFilterErrorDispatch() {
        return false;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
                                    final FilterChain chain) throws ServletException, IOException {
        final ServiceAccountAuthentication auth = authenticate(bearerToken(request));
        if (auth == null && request.getDispatcherType() == jakarta.servlet.DispatcherType.ERROR) {
            chain.doFilter(request, response); // already rejected on the original dispatch
            return;
        }
        if (auth == null) {
            response.setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        final SecurityContext previous = SecurityContextHolder.getContext();
        final SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(auth);
        SecurityContextHolder.setContext(context);
        try {
            chain.doFilter(request, response);
        } finally {
            SecurityContextHolder.setContext(previous);
        }
    }

    private ServiceAccountAuthentication authenticate(final String token) {
        try {
            final OAuth2Authorization authorization = authorizations.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
            if (authorization == null || !AuthorizationGrantType.CLIENT_CREDENTIALS.equals(authorization.getAuthorizationGrantType())) {
                return null;
            }
            final OAuth2Authorization.Token<OAuth2AccessToken> access = authorization.getAccessToken();
            if (access == null || !access.isActive() || !token.equals(access.getToken().getTokenValue())) {
                return null;
            }
            final Map<String, Object> claims = access.getClaims();
            final String realm = realmOf(claims == null ? null : claims.get("iss"));
            final Object clientId = claims.get("client_id") != null ? claims.get("client_id") : claims.get("sub");
            if (realm == null || clientId == null) {
                return null;
            }
            final List<ServiceAccountRoleDto> roles = clientRoles.serviceAccountRoles(RealmScopedKey.pack(realm, clientId.toString()));
            final List<GrantedAuthority> authorities = (roles == null ? List.<ServiceAccountRoleDto>of() : roles).stream()
                    .filter(r -> r.roleType() == null || "REALM".equalsIgnoreCase(r.roleType()))
                    .map(r -> (GrantedAuthority) new SimpleGrantedAuthority(r.roleName() + "_" + realm))
                    .toList();
            return new ServiceAccountAuthentication(clientId.toString(), realm, authorities);
        } catch (final RuntimeException e) {
            LOG.warn("Admin bearer token rejected: {}", e.getMessage());
            return null;
        }
    }

    /** {@code https://host/realms/{realm}} → {@code realm}. */
    static String realmOf(final Object issuer) {
        if (issuer == null) {
            return null;
        }
        final String iss = issuer.toString();
        final int i = iss.lastIndexOf("/realms/");
        if (i < 0) {
            return null;
        }
        final String realm = iss.substring(i + "/realms/".length());
        return realm.isBlank() || realm.contains("/") ? null : realm;
    }

    private static boolean isAdminPath(final HttpServletRequest request) {
        final Object forwarded = request.getAttribute(jakarta.servlet.RequestDispatcher.ERROR_REQUEST_URI);
        final String uri = forwarded != null ? forwarded.toString() : request.getRequestURI();
        final String ctx = request.getContextPath();
        final String path = ctx != null && !ctx.isEmpty() && uri.startsWith(ctx) ? uri.substring(ctx.length()) : uri;
        return path.startsWith("/admin/");
    }

    private static String bearerToken(final HttpServletRequest request) {
        final String header = request.getHeader("Authorization");
        if (header == null || !header.regionMatches(true, 0, BEARER, 0, BEARER.length())) {
            return null;
        }
        final String token = header.substring(BEARER.length()).trim();
        return token.isEmpty() ? null : token;
    }

    /** A service account authenticated by its bearer token for one admin API request. */
    public static final class ServiceAccountAuthentication extends AbstractAuthenticationToken {
        private final String clientId;
        private final String realm;

        ServiceAccountAuthentication(final String clientId, final String realm, final List<GrantedAuthority> authorities) {
            super(authorities);
            this.clientId = clientId;
            this.realm = realm;
            setAuthenticated(true);
        }

        public String realm() {
            return realm;
        }

        @Override
        public Object getCredentials() {
            return "";
        }

        @Override
        public Object getPrincipal() {
            return clientId;
        }

        @Override
        public String getName() {
            return clientId;
        }
    }
}
