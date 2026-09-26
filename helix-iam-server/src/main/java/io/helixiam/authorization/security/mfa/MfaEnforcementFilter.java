/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.mfa;

import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.mfa.domain.MfaAuthentication;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.service.mfa.MfaPolicyService;
import io.helixiam.authorization.service.mfa.TotpService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * 1.0 item 6: no authorization code (or device approval) for a user who has not passed the second factor in this
 * sign-in when their realm requires it — or when they have enrolled TOTP. Runs in front of
 * {@code /oauth2/authorize} and {@code /oauth2/device_verification}, so every way of reaching them (password
 * login, the flow engine, federated login, a stale session) is covered.
 *
 * <p>Such a request is saved, the session is put back behind the MFA gate ({@link MfaAuthentication}) and the
 * browser is sent to TOTP ({@code /mfa/totp}) or, if the user has not enrolled yet, to enrolment
 * ({@code /mfa/enable}). Passing it marks the session ({@link MfaSessionState}) and resumes the request.
 */
public class MfaEnforcementFilter extends OncePerRequestFilter {

    private final MfaPolicyService policy;
    private final TotpService totp;
    private final HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
    private final HttpSessionSecurityContextRepository contexts = new HttpSessionSecurityContextRepository();

    public MfaEnforcementFilter(final MfaPolicyService policy, final TotpService totp) {
        this.policy = policy;
        this.totp = totp;
    }

    @Override
    protected boolean shouldNotFilter(final HttpServletRequest request) {
        final String path = request.getServletPath();
        return !("/oauth2/authorize".equals(path) || "/oauth2/device_verification".equals(path));
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
                                    final FilterChain chain) throws ServletException, IOException {
        final Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || auth instanceof MfaAuthentication
                || !(auth.getPrincipal() instanceof UserCredentials user)) {
            chain.doFilter(request, response); // anonymous / gated / machine: the normal chain handles it
            return;
        }
        final String userId = user.getUsername();
        if (MfaSessionState.isVerified(request, userId)) {
            chain.doFilter(request, response);
            return;
        }
        final boolean enrolled = totp.isEnrolled(userId);
        if (!enrolled && !policy.required(RealmContextHolder.get())) {
            chain.doFilter(request, response);
            return;
        }
        requestCache.saveRequest(request, response);
        final SecurityContext gated = SecurityContextHolder.createEmptyContext();
        gated.setAuthentication(new MfaAuthentication(auth));
        SecurityContextHolder.setContext(gated);
        contexts.saveContext(gated, request, response);
        response.sendRedirect(request.getContextPath() + (enrolled ? "/mfa/totp" : "/mfa/enable"));
    }
}
