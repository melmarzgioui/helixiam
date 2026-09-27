/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.session.AuthTimeStamper;
import io.helixiam.common.log.LogSafe;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * B1: ends a browser session that "sign out everywhere else" or an account deletion revoked
 * ({@link SessionRevocation}) on its next request — the page, {@code /oauth2/authorize} (so no silent sign-in), the
 * admin console. The request then continues anonymously, which sends a page to the sign-in form. Static files are not
 * checked. Runs early in both browser filter chains; it reads the authentication from the session itself. A session
 * that stays signed in is recorded in the {@link BrowserSessionRegistry} (rc.6 item 7b: the account console's session
 * list).
 */
public class SessionRevocationFilter extends OncePerRequestFilter {

    private static final Logger LOG = LogManager.getLogger(SessionRevocationFilter.class);

    private final SessionRevocation revocation;
    private final BrowserSessionRegistry browserSessions;

    /**
     * @param browserSessions records each signed-in browser that stays signed in, for the account console's session
     *                        list (rc.6 item 7b); null records nothing
     */
    public SessionRevocationFilter(final SessionRevocation revocation, final BrowserSessionRegistry browserSessions) {
        this.revocation = revocation;
        this.browserSessions = browserSessions;
    }

    /**
     * The session's authentication, read from the session itself: the filter may run before the chain has loaded the
     * security context into the holder.
     */
    private static Authentication authentication(final HttpSession session) {
        final Authentication loaded = SecurityContextHolder.getContext().getAuthentication();
        if (loaded != null) {
            return loaded;
        }
        return session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)
                instanceof SecurityContext context ? context.getAuthentication() : null;
    }

    @Override
    protected boolean shouldNotFilter(final HttpServletRequest request) {
        final String path = request.getServletPath();
        return path.startsWith("/css/") || path.startsWith("/js/") || path.startsWith("/img/")
                || path.startsWith("/fonts/") || path.startsWith("/theme/assets/") || "/theme.css".equals(path);
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
                                    final FilterChain chain) throws ServletException, IOException {
        final HttpSession session = request.getSession(false);
        final Authentication auth = session == null ? null : authentication(session);
        if (session != null && auth != null && auth.getPrincipal() instanceof UserCredentials user
                && user.getUserId() != null) {
            final Long secs = new AuthTimeStamper().read(request);
            final Long millis = AuthTimeStamper.readMillis(request);
            final Long authTime = millis != null ? millis : secs == null ? null : secs * 1000L; // stamped before B1
            final Long kept = session.getAttribute(SessionRevocation.KEPT_ATTRIBUTE) instanceof Long k ? k : null;
            if (!SessionRevocation.valid(revocation.state(user.getUserId()), authTime, session.getCreationTime(), kept)) {
                LOG.info("Ending a revoked browser session of user {}", LogSafe.sanitize(user.getUserId()));
                session.invalidate();
                SecurityContextHolder.clearContext();
            } else if (browserSessions != null) {
                browserSessions.touch(request, session, user.getUserId());
            }
        }
        chain.doFilter(request, response);
    }
}
