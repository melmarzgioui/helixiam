/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.adminrbac;

import io.helixiam.authorization.service.adminrbac.AdminGrantGuard;
import io.helixiam.authorization.service.adminrbac.PrivilegedPrincipalGuard;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.util.UrlPathHelper;

import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * Security review H5, the controller layer of {@link PrivilegedPrincipalGuard}: every admin action on
 * {@code /admin/realms/{realm}/users/{userId}/…} and {@code /admin/realms/{realm}/clients/{id}/…} that targets a
 * principal more privileged than the caller is answered {@code 403} before the controller runs (the services check
 * again). Reads are not actions, except revealing a client secret. Not targeted here: session revocation (allowed),
 * role assignment and service-account roles ({@link AdminGrantGuard} decides those), and the verification e-mail.
 */
public class PrivilegedPrincipalInterceptor implements HandlerInterceptor {

    private static final Set<String> USER_EXEMPT = Set.of("sessions", "roles", "send-verification-email");
    private static final UrlPathHelper DECODED = decoded();

    private static UrlPathHelper decoded() {
        final UrlPathHelper h = new UrlPathHelper();
        h.setUrlDecode(true);
        h.setRemoveSemicolonContent(true);
        h.setDefaultEncoding("UTF-8");
        return h;
    }

    private final PrivilegedPrincipalGuard guard;

    public PrivilegedPrincipalInterceptor(final PrivilegedPrincipalGuard guard) {
        this.guard = guard;
    }

    @Override
    public boolean preHandle(final HttpServletRequest request, final HttpServletResponse response,
                             final Object handler) throws Exception {
        final String[] seg = DECODED.getPathWithinApplication(request).substring(1).split("/");
        // admin / realms / {realm} / users|clients / {id} [/ sub …]
        if (seg.length < 5 || !"admin".equals(seg[0]) || !"realms".equals(seg[1])) {
            return true;
        }
        final String realm = seg[2];
        final String id = seg[4];
        final String sub = seg.length > 5 ? seg[5] : null;
        final boolean read = "GET".equalsIgnoreCase(request.getMethod()) || "HEAD".equalsIgnoreCase(request.getMethod())
                || "OPTIONS".equalsIgnoreCase(request.getMethod());
        try {
            if ("users".equals(seg[3])) {
                if (read || "import".equals(id) || (sub != null && USER_EXEMPT.contains(sub))) {
                    return true;
                }
                guard.requireMayActOnUser(realm, id, "This action");
            } else if ("clients".equals(seg[3])) {
                final boolean secretRead = read && "secret".equals(sub);
                if (read && !secretRead) {
                    return true;
                }
                if ("service-account".equals(sub)) {
                    guard.requireMayChangeSignInClient(realm, id, "Changing service-account roles");
                    return true;
                }
                guard.requireMayActOnClient(realm, id, secretRead ? "Revealing this client's secret" : "This action");
                if (!read && sub != null) {
                    // Roles, mappers, authorization, token exchange of the console or CLI client: realm-admin.
                    guard.requireMayChangeSignInClient(realm, id, "Changing " + sub);
                }
            }
            return true;
        } catch (final AdminGrantGuard.AdminGrantDeniedException e) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getOutputStream().write(("{\"error\":\"forbidden\",\"message\":\""
                    + e.getMessage().replace("\"", "'") + "\"}").getBytes(StandardCharsets.UTF_8));
            return false;
        }
    }
}
