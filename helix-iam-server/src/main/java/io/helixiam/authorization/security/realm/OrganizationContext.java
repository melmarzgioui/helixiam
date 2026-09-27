/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.realm;

import io.helixiam.authorization.service.org.OrganizationBrandingService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

/**
 * 1.0 item 7 (branding): the organization a sign-in is for. An {@code organization} parameter (id or name) on
 * {@code /oauth2/authorize} puts an enabled organization of the realm in context for the rest of that sign-in
 * (login, MFA, consent); an unknown value clears it. Stored per realm in the HTTP session.
 */
public class OrganizationContext extends OncePerRequestFilter {

    static final String ATTRIBUTE = "HELIX_ORGANIZATION_CONTEXT";
    private static final String PARAM = "organization";

    private final OrganizationBrandingService organizations;

    public OrganizationContext(final OrganizationBrandingService organizations) {
        this.organizations = organizations;
    }

    @Override
    protected boolean shouldNotFilter(final HttpServletRequest request) {
        return !"/oauth2/authorize".equals(request.getServletPath()) || request.getParameter(PARAM) == null;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
                                    final FilterChain chain) throws ServletException, IOException {
        final String realm = RealmContextHolder.get();
        final Optional<String> orgId = organizations.resolveHint(realm, request.getParameter(PARAM));
        if (orgId.isPresent()) {
            request.getSession(true).setAttribute(ATTRIBUTE, realm + "|" + orgId.get());
        } else {
            final HttpSession session = request.getSession(false);
            if (session != null) {
                session.removeAttribute(ATTRIBUTE);
            }
        }
        chain.doFilter(request, response);
    }

    /** The organization in context for {@code realm} in this session, if any. */
    public static Optional<String> current(final HttpServletRequest request, final String realm) {
        final HttpSession session = request == null ? null : request.getSession(false);
        final Object value = session == null ? null : session.getAttribute(ATTRIBUTE);
        if (value instanceof String s && realm != null && s.startsWith(realm + "|")) {
            return Optional.of(s.substring(realm.length() + 1));
        }
        return Optional.empty();
    }
}
