/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.oidc;

import io.helixiam.authorization.security.mfa.domain.MfaAuthentication;
import io.helixiam.authorization.security.session.AuthTimeStamper;
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
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.function.LongSupplier;

/**
 * Helix IAM SSO P2: OIDC {@code prompt}/{@code max_age} handling at the authorization endpoint, which
 * Spring Authorization Server does not implement natively. Runs before the SAS authorization-endpoint
 * filter on the same chain (where the browser session + SecurityContext are present):
 *
 * <ul>
 *   <li>{@code prompt=none} — silent SSO: pass straight through when there is a valid (and not
 *       {@code max_age}-expired) session so SAS issues a code with no UI; otherwise return the OIDC
 *       error {@code login_required} as a redirect to the client's <em>registered</em> redirect_uri
 *       (validated first — never an open redirect).</li>
 *   <li>{@code prompt=login} or an expired {@code max_age} — force re-authentication by clearing the
 *       session authentication, so the SAS entry point bounces the user to {@code /login} (saving the
 *       authorize request, which P1 then resumes). {@code prompt=login} forces once per request: the
 *       resumed request, whose {@code auth_time} is newer than when the prompt was first seen, passes.</li>
 * </ul>
 */
public class PromptAndMaxAgeAuthorizeFilter extends OncePerRequestFilter {

    /** Default session key Spring Security uses to persist the {@code SecurityContext}. */
    private static final String SPRING_SECURITY_CONTEXT_KEY = "SPRING_SECURITY_CONTEXT";
    private static final String AUTHORIZE_PATH = "/oauth2/authorize";
    /** Session attribute: epoch second a {@code prompt=login} request was first seen and not yet satisfied. */
    static final String PROMPT_LOGIN_SINCE = "HELIX_PROMPT_LOGIN_SINCE";

    private final RegisteredClientRepository clients;
    private final AuthTimeStamper authTimeStamper;
    private final io.helixiam.authorization.security.realm.RealmSettingsResolver realmSettings;
    private final LongSupplier nowEpochSeconds;

    public PromptAndMaxAgeAuthorizeFilter(final RegisteredClientRepository clients, final AuthTimeStamper authTimeStamper,
                                          final io.helixiam.authorization.security.realm.RealmSettingsResolver realmSettings) {
        this(clients, authTimeStamper, realmSettings, () -> Instant.now().getEpochSecond());
    }

    /** Test seam: inject a fixed clock. */
    PromptAndMaxAgeAuthorizeFilter(final RegisteredClientRepository clients, final AuthTimeStamper authTimeStamper,
                                   final io.helixiam.authorization.security.realm.RealmSettingsResolver realmSettings,
                                   final LongSupplier nowEpochSeconds) {
        this.clients = clients;
        this.authTimeStamper = authTimeStamper;
        this.realmSettings = realmSettings;
        this.nowEpochSeconds = nowEpochSeconds;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
                                    final FilterChain chain) throws ServletException, IOException {
        if (!request.getServletPath().endsWith(AUTHORIZE_PATH)) {
            chain.doFilter(request, response);
            return;
        }

        final String prompt = request.getParameter("prompt");
        final boolean authed = isFullyAuthenticated(request);
        // Re-auth is forced by an expired request max_age OR the realm's hard SSO max-lifetime (P3).
        final boolean tooOld = authed && (maxAgeExceeded(request) || realmMaxLifetimeExceeded(request));

        if ("none".equals(prompt)) {
            if (authed && !tooOld) {
                chain.doFilter(request, response); // silent SSO — SAS issues the code
            } else {
                writeLoginRequired(request, response);
            }
            return;
        }

        if ("login".equals(prompt)) {
            handlePromptLogin(request, authed);
        } else if (tooOld) {
            forceReauth(request); // SAS entry point will redirect to /login and save the request
        }
        chain.doFilter(request, response);
    }

    /**
     * A2: {@code prompt=login} forces ONE interactive login per authorization request. The first time the
     * request is seen we note the moment ({@link #PROMPT_LOGIN_SINCE}) and drop any session authentication, so
     * the user signs in. When the login success handler resumes the saved request (which still carries
     * {@code prompt=login}), the session's {@code auth_time} is at or after that moment: the user re-authenticated
     * for this request, so it passes through (and the marker is consumed) instead of being forced again — which
     * used to send the user back to {@code /login} forever.
     */
    private void handlePromptLogin(final HttpServletRequest request, final boolean authed) {
        final HttpSession session = request.getSession(false);
        final Object since = session == null ? null : session.getAttribute(PROMPT_LOGIN_SINCE);
        final Long authTime = authTimeStamper.read(request);
        if (authed && since instanceof Long sinceSeconds && authTime != null && authTime >= sinceSeconds) {
            session.removeAttribute(PROMPT_LOGIN_SINCE); // re-authenticated for this request: honour it once
            return;
        }
        // Not yet re-authenticated for this request: note when it was seen, then make the user sign in.
        forceReauth(request);
        request.getSession(true).setAttribute(PROMPT_LOGIN_SINCE, nowEpochSeconds.getAsLong());
    }

    private boolean isFullyAuthenticated(final HttpServletRequest request) {
        final Authentication a = currentAuthentication(request);
        return a != null && a.isAuthenticated()
                && !(a instanceof AnonymousAuthenticationToken)
                && !(a instanceof MfaAuthentication); // the post-password gate is not yet fully authenticated
    }

    /**
     * The request's authentication — from {@link SecurityContextHolder} when populated, else from the
     * persisted {@code SPRING_SECURITY_CONTEXT} session attribute (Spring Session's deferred context may
     * not be resolved at this filter's position).
     */
    private Authentication currentAuthentication(final HttpServletRequest request) {
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

    /** True only when a parseable {@code max_age} is present and the session's auth_time is older than it. */
    private boolean maxAgeExceeded(final HttpServletRequest request) {
        final String maxAge = request.getParameter("max_age");
        if (maxAge == null || maxAge.isBlank()) {
            return false;
        }
        final long max;
        try {
            max = Long.parseLong(maxAge.trim());
        } catch (final NumberFormatException e) {
            return false;
        }
        final Long authTime = authTimeStamper.read(request);
        return authTime == null || nowEpochSeconds.getAsLong() - authTime > max;
    }

    /** True when the realm's hard SSO max-lifetime has elapsed since the session's auth_time. */
    private boolean realmMaxLifetimeExceeded(final HttpServletRequest request) {
        try {
            final var settings = realmSettings.get(io.helixiam.authorization.security.realm.RealmContextHolder.get());
            if (settings == null || settings.ssoSessionMaxLifetimeSeconds() <= 0) {
                return false;
            }
            final Long authTime = authTimeStamper.read(request);
            return authTime != null && nowEpochSeconds.getAsLong() - authTime > settings.ssoSessionMaxLifetimeSeconds();
        } catch (final RuntimeException e) {
            return false; // never block the authorize endpoint on a settings lookup
        }
    }

    /** Drop the session authentication (and auth_time) so the next step re-authenticates the user. */
    private void forceReauth(final HttpServletRequest request) {
        SecurityContextHolder.clearContext();
        final HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(SPRING_SECURITY_CONTEXT_KEY);
            session.removeAttribute(AuthTimeStamper.HELIX_AUTH_TIME);
        }
    }

    /** OIDC {@code login_required}: redirect to the registered redirect_uri, or fail closed if invalid. */
    private void writeLoginRequired(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        final String clientId = request.getParameter("client_id");
        final String redirectUri = request.getParameter("redirect_uri");
        final String state = request.getParameter("state");
        final RegisteredClient client = clientId == null ? null : clients.findByClientId(clientId);
        if (client == null || redirectUri == null || !client.getRedirectUris().contains(redirectUri)) {
            // Never redirect to an unregistered URI — that would be an open redirect.
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "prompt=none requires a valid client_id and a registered redirect_uri");
            return;
        }
        final StringBuilder url = new StringBuilder(redirectUri)
                .append(redirectUri.contains("?") ? "&" : "?")
                .append("error=login_required");
        if (state != null && !state.isBlank()) {
            url.append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8));
        }
        response.sendRedirect(url.toString());
    }
}
