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
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

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
    private final RegisteredClientRepository clients;

    /** Spring Security's session key of the persisted {@code SecurityContext}. */
    static final String SPRING_SECURITY_CONTEXT_KEY = HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

    public MfaEnforcementFilter(final MfaPolicyService policy, final TotpService totp) {
        this(policy, totp, null);
    }

    /** @param clients to answer {@code prompt=none} with {@code interaction_required} (null: always the second step) */
    public MfaEnforcementFilter(final MfaPolicyService policy, final TotpService totp,
                                final RegisteredClientRepository clients) {
        this.policy = policy;
        this.totp = totp;
        this.clients = clients;
    }

    @Override
    protected boolean shouldNotFilter(final HttpServletRequest request) {
        final String path = request.getServletPath();
        return !("/oauth2/authorize".equals(path) || "/oauth2/device_verification".equals(path));
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
                                    final FilterChain chain) throws ServletException, IOException {
        if (!gate(request, response)) {
            chain.doFilter(request, response);
        }
    }

    /**
     * B1: the same check for any other page that must not be used before the second factor (the account console).
     * Returns true when the request was saved and the browser sent to the second step (the caller stops there).
     *
     * <p>Security (MFA gate): the sign-in is read from {@link SecurityContextHolder} and, when that is empty, from the
     * session's persisted {@code SPRING_SECURITY_CONTEXT}. In the authorization-server chain this filter runs before
     * the session's context is loaded into the holder, so reading the holder alone saw nobody and let every full
     * session through: a federated sign-in, or a session from before the realm required a second factor, was issued a
     * code without one.
     */
    public boolean gate(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        final java.util.Optional<String> step = pendingSecondStep(request);
        if (step.isEmpty()) {
            return false;
        }
        holdForSecondStep(request, response);
        if (promptNone(request) && sendInteractionRequired(request, response)) {
            return true; // prompt=none: no page may be shown; the client is told instead
        }
        requestCache.saveRequest(request, response);
        response.sendRedirect(request.getContextPath() + step.get());
        return true;
    }

    /**
     * The second-step page ({@code /mfa/totp}, or {@code /mfa/enable} when the user has not enrolled) this request's
     * sign-in must pass before anything is issued to it; empty when there is nothing to hold (anonymous, already held,
     * a machine, the second factor passed in this sign-in, or neither the realm nor the user requires one). The
     * sign-in is read from {@link SecurityContextHolder}, else from the session's persisted context. Changes nothing.
     */
    public java.util.Optional<String> pendingSecondStep(final HttpServletRequest request) {
        final Authentication auth = signIn(request);
        if (auth == null || !auth.isAuthenticated() || auth instanceof MfaAuthentication
                || !(auth.getPrincipal() instanceof UserCredentials user)) {
            return java.util.Optional.empty(); // anonymous / gated / machine: the normal chain handles it
        }
        final String userId = user.getUsername();
        if (MfaSessionState.isVerified(request, userId)) {
            return java.util.Optional.empty();
        }
        final boolean enrolled = totp.isEnrolled(userId);
        if (!enrolled && !policy.required(RealmContextHolder.get())) {
            return java.util.Optional.empty();
        }
        return java.util.Optional.of(enrolled ? "/mfa/totp" : "/mfa/enable");
    }

    /**
     * Puts the session behind the second step (the sign-in becomes an unauthenticated {@link MfaAuthentication} until
     * the factor passes) and saves {@code request} to resume afterwards. Call only when {@link #pendingSecondStep} is
     * present; the caller then sends the browser to that page.
     */
    public void holdForSecondStep(final HttpServletRequest request, final HttpServletResponse response) {
        final Authentication held = SecurityContextHolder.getContext().getAuthentication();
        final boolean fromHolder = held != null && held.isAuthenticated() && !(held instanceof AnonymousAuthenticationToken);
        final Authentication auth = fromHolder ? held : sessionAuthentication(request);
        final SecurityContext gated = SecurityContextHolder.createEmptyContext();
        gated.setAuthentication(new MfaAuthentication(auth));
        if (fromHolder) {
            // The chain saves the holder's context at the end of the request: it must be the gated one.
            SecurityContextHolder.setContext(gated);
        }
        // From the session only: nothing loaded the holder for this request and nothing would clear it, so it is left
        // alone (a context set here would leak to the next request on this thread).
        contexts.saveContext(gated, request, response);
    }

    /** Resumes {@code request} after the second step (the saved request the success handlers redirect to). */
    public void saveRequest(final HttpServletRequest request, final HttpServletResponse response) {
        requestCache.saveRequest(request, response);
    }

    private static Authentication signIn(final HttpServletRequest request) {
        final Authentication held = SecurityContextHolder.getContext().getAuthentication();
        return held != null && held.isAuthenticated() && !(held instanceof AnonymousAuthenticationToken)
                ? held : sessionAuthentication(request);
    }

    /** The persisted sign-in of the session, if any (never creates a session). */
    private static Authentication sessionAuthentication(final HttpServletRequest request) {
        final HttpSession session = request.getSession(false);
        return session != null && session.getAttribute(SPRING_SECURITY_CONTEXT_KEY) instanceof SecurityContext ctx
                ? ctx.getAuthentication() : null;
    }

    private static boolean promptNone(final HttpServletRequest request) {
        final String prompt = request.getParameter("prompt");
        return prompt != null && java.util.Arrays.asList(prompt.trim().split("\\s+")).contains("none")
                && "/oauth2/authorize".equals(request.getServletPath());
    }

    /**
     * OpenID Connect: with {@code prompt=none} the second step cannot be shown, so the client gets
     * {@code error=interaction_required} (with its {@code state}) at its redirect URI — only one registered for the
     * client. False when that cannot be done safely (then the user is sent to the second step as usual).
     */
    private boolean sendInteractionRequired(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException {
        final String clientId = request.getParameter("client_id");
        final RegisteredClient client = clients == null || clientId == null ? null : clients.findByClientId(clientId);
        if (client == null) {
            return false;
        }
        final String requested = request.getParameter("redirect_uri");
        final String redirect = requested != null ? (client.getRedirectUris().contains(requested) ? requested : null)
                : client.getRedirectUris().size() == 1 ? client.getRedirectUris().iterator().next() : null;
        if (redirect == null) {
            return false;
        }
        final UriComponentsBuilder target = UriComponentsBuilder.fromUriString(redirect)
                .queryParam("error", "interaction_required")
                .queryParam("error_description", "A second factor is required");
        final String state = request.getParameter("state");
        if (state != null) {
            target.queryParam("state", state);
        }
        response.sendRedirect(target.encode().build().toUriString());
        return true;
    }
}
