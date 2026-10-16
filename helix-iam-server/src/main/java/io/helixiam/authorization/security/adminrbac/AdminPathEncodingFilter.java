/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.adminrbac;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Security review (authorization bypass): the structural part of an admin path —
 * {@code /admin/realms/{realmId}/{group}}, or the first two segments of any other {@code /admin} path — must be plain
 * text. A percent-encoded character there ({@code /admin/realms/r/k%65ys}) is answered {@code 400} before any
 * authorization runs: those segments are realm ids ({@code [A-Za-z0-9._-]}) and fixed route names, which never need
 * encoding. Deeper segments (a SAML entity id such as {@code urn%3Aexample%3Asp}, a scope name) may stay encoded:
 * they never decide the required permission, which {@link AdminRoutePermissions} reads from the decoded path anyway.
 * A double-encoded {@code %25} is refused anywhere under {@code /admin}.
 */
public class AdminPathEncodingFilter extends OncePerRequestFilter {

    @Override
    protected boolean shouldNotFilter(final HttpServletRequest request) {
        return !rawAdminPath(request).startsWith("/admin");
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
                                    final FilterChain chain) throws ServletException, IOException {
        if (refused(rawAdminPath(request))) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setContentType("application/json");
            response.getOutputStream().write(("{\"error\":\"invalid_request\",\"message\":\"Percent-encoded "
                    + "characters are not allowed in the realm or route part of an admin path.\"}")
                    .getBytes(StandardCharsets.UTF_8));
            return;
        }
        chain.doFilter(request, response);
    }

    /** Whether the raw (still encoded) admin path is refused. */
    static boolean refused(final String rawPath) {
        if (rawPath.startsWith("/admin%")) {
            return true; // "/admin%2F…": an encoded separator right after the admin prefix
        }
        if (!rawPath.startsWith("/admin/")) {
            return false;
        }
        if (rawPath.contains("%25")) {
            return true;
        }
        final String[] seg = rawPath.substring(1).split("/", -1);
        final int structural = seg.length >= 2 && "realms".equals(seg[1]) ? 4 : 2;
        for (int i = 0; i < Math.min(structural, seg.length); i++) {
            if (seg[i].indexOf('%') >= 0) {
                return true;
            }
        }
        return false;
    }

    private static String rawAdminPath(final HttpServletRequest request) {
        final String uri = request.getRequestURI() == null ? "" : request.getRequestURI();
        final String ctx = request.getContextPath();
        return ctx != null && !ctx.isEmpty() && uri.startsWith(ctx) ? uri.substring(ctx.length()) : uri;
    }
}
