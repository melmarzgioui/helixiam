/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.impersonation;

import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.federation.FederatedSessionEstablisher;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.security.realm.SessionPolicyApplier;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

/**
 * Helix IAM B4: admin impersonation. Establishes a browser session AS a target user — passwordlessly,
 * reusing the same {@link FederatedSessionEstablisher#persist} seam the federation broker uses after an
 * external login. The original admin is recorded on the session ({@link #IMPERSONATOR_ATTR}) so the app
 * can surface a banner and {@link #stop} can end it. Because the session goes through the normal
 * SecurityContextRepository save, it participates in SSO session listing + logout automatically.
 *
 * <p>Security: {@code impersonate} trusts the {@code userId} as already authorised — it must only be
 * reached from the admin-guarded {@code /admin/**} surface (RBAC + audit), never from an end-user path.
 */
@Service
public class ImpersonationService {

    /** Session attribute holding the impersonating admin's actor name (presence = impersonation active). */
    public static final String IMPERSONATOR_ATTR = "HELIX_IMPERSONATOR";

    private static final Logger LOG = LogManager.getLogger(ImpersonationService.class);

    private final FederatedSessionEstablisher establisher;
    private final String spBaseUrl;
    private final SessionPolicyApplier sessionPolicyApplier;

    @Autowired
    public ImpersonationService(final FederatedSessionEstablisher establisher,
                                @Value("${sp.base.url:/}") final String spBaseUrl,
                                final SessionPolicyApplier sessionPolicyApplier) {
        this.establisher = establisher;
        this.spBaseUrl = spBaseUrl;
        this.sessionPolicyApplier = sessionPolicyApplier;
    }

    /** The result of starting impersonation: who you are now + where to land. */
    public record Result(String userId, String username, String redirectUrl) {
    }

    /**
     * Start impersonating {@code userId}: load them passwordlessly, install an authenticated session,
     * and stamp the impersonating admin on it. Returns the target identity + the landing URL.
     */
    public Result impersonate(final String realm, final String userId, final String adminActor,
                              final HttpServletRequest request, final HttpServletResponse response) {
        final UserCredentials user = establisher.loadUser(userId);
        final Authentication auth =
                UsernamePasswordAuthenticationToken.authenticated(user, null, user.getAuthorities());
        // Mark the session BEFORE persisting so the impersonation flag rides the same session.
        request.getSession().setAttribute(IMPERSONATOR_ATTR, adminActor);
        establisher.persist(auth, request, response);
        if (sessionPolicyApplier != null) {
            try {
                sessionPolicyApplier.applyOnLogin(request, realm); // SSO P3: same idle/max policy as a real login
            } catch (final RuntimeException e) {
                LOG.debug("Impersonation session-policy apply skipped: {}", e.getMessage());
            }
        }
        LOG.info("Admin {} is now impersonating user {} in realm {}", adminActor, userId, realm);
        return new Result(userId, user.getUsername(), spBaseUrl);
    }

    /**
     * End impersonation: returns the impersonating admin's name (or {@code null} if the session was not
     * impersonating) and invalidates the session so the impersonated identity is fully dropped.
     */
    public String stop(final HttpServletRequest request, final HttpServletResponse response) {
        final HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        final Object impersonator = session.getAttribute(IMPERSONATOR_ATTR);
        if (impersonator == null) {
            return null;
        }
        session.invalidate(); // drop the impersonated identity entirely
        LOG.info("Impersonation by {} ended", impersonator);
        return impersonator.toString();
    }

    /** Whether the current request's session is an active impersonation (for banners). */
    public static boolean isImpersonating(final HttpServletRequest request) {
        final HttpSession session = request.getSession(false);
        return session != null && session.getAttribute(IMPERSONATOR_ATTR) != null;
    }

    /** Convenience for callers that already know the realm from the context. */
    public Result impersonate(final String userId, final String adminActor,
                              final HttpServletRequest request, final HttpServletResponse response) {
        return impersonate(RealmContextHolder.get(), userId, adminActor, request, response);
    }
}
