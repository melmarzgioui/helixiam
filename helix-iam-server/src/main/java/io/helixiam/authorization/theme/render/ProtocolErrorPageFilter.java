/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.render;

import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.common.log.LogSafe;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Item 6: a browser that ends on an error of a realm endpoint gets a page in the realm's theme instead of Spring's
 * plain error page. The OAuth / OIDC endpoints answer an error they cannot send back to the client (an unknown
 * {@code client_id}, a redirect URI that is not registered, a request without {@code client_id}, an end-session
 * request without {@code id_token_hint}) with {@code sendError(400, "[code] OAuth 2.0 Parameter: name")}, which
 * Spring renders as its "Whitelabel" page, unthemed and outside the realm.
 *
 * <p>For a realm request whose {@code Accept} asks for HTML, this filter catches a {@code sendError} with a 4xx
 * status and, if nothing was written, renders {@code protocol-error} ({@link ThemedPageRenderer}) with the same
 * status: a title, a message chosen from a fixed set, the OAuth error code when it is a standard one, and a reference
 * that is also logged. Nothing from the request (parameters, the error description) is shown. Any other request
 * (an API client, a 5xx, a request outside a realm) keeps the usual error handling, so API clients still get JSON.
 */
public class ProtocolErrorPageFilter extends OncePerRequestFilter {

    /** The template rendered. */
    public static final String TEMPLATE = "protocol-error";

    private static final Logger LOG = LogManager.getLogger(ProtocolErrorPageFilter.class);

    /** Standard OAuth 2.0 / OIDC error codes that may be shown (anything else is not). */
    static final Set<String> CODES = Set.of("invalid_request", "invalid_client", "invalid_grant", "unauthorized_client",
            "unsupported_grant_type", "invalid_scope", "access_denied", "unsupported_response_type", "server_error",
            "temporarily_unavailable", "invalid_token", "insufficient_scope", "invalid_redirect_uri", "invalid_target",
            "invalid_request_uri", "invalid_request_object", "login_required", "interaction_required",
            "consent_required");

    private final ThemedPageRenderer renderer;

    public ProtocolErrorPageFilter(final ThemedPageRenderer renderer) {
        this.renderer = renderer;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
                                    final FilterChain chain) throws ServletException, IOException {
        if (RealmContextHolder.get() == null || !wantsHtml(request)) {
            chain.doFilter(request, response);
            return;
        }
        final CapturingResponse capturing = new CapturingResponse(response);
        chain.doFilter(request, capturing);
        if (capturing.status == 0) {
            return;
        }
        if (response.isCommitted()) {
            return; // something was already written; nothing to replace
        }
        final Kind kind = classify(request, capturing.status, capturing.message);
        final String code = code(capturing.message);
        final String reference = UUID.randomUUID().toString();
        LOG.info("Protocol error page {} ({}) for {} in realm {} [reference={}]", capturing.status,
                LogSafe.sanitize(capturing.message), LogSafe.sanitize(request.getRequestURI()),
                LogSafe.sanitize(RealmContextHolder.get()), reference);
        try {
            response.resetBuffer();
            renderer.render(TEMPLATE, Map.of("errorKind", kind.key, "errorCode", code == null ? "" : code,
                    "errorReference", reference), capturing.status, request, response);
        } catch (final Exception e) {
            LOG.warn("The themed error page could not be rendered [reference={}]: {}", reference,
                    LogSafe.sanitize(e.toString()));
            if (!response.isCommitted()) {
                response.sendError(capturing.status);
            }
        }
    }

    /** What went wrong, as far as the page tells the user. */
    enum Kind {
        CLIENT("client"), REDIRECT("redirect"), LOGOUT("logout"), REQUEST("request"), NOT_FOUND("notFound"),
        FORBIDDEN("forbidden"), GENERIC("generic");

        final String key;

        Kind(final String key) {
            this.key = key;
        }
    }

    /**
     * The kind of error, from the status, the endpoint and the error message (written by the server, e.g.
     * {@code [invalid_request] OAuth 2.0 Parameter: client_id}; never shown).
     */
    static Kind classify(final HttpServletRequest request, final int status, final String message) {
        final String path = request.getServletPath() == null ? "" : request.getServletPath();
        final String m = message == null ? "" : message;
        if (status == HttpServletResponse.SC_NOT_FOUND) {
            return Kind.NOT_FOUND;
        }
        if (status == HttpServletResponse.SC_FORBIDDEN || status == HttpServletResponse.SC_UNAUTHORIZED) {
            return Kind.FORBIDDEN;
        }
        if (status != HttpServletResponse.SC_BAD_REQUEST) {
            return Kind.GENERIC;
        }
        if (path.endsWith("/connect/logout")) {
            return Kind.LOGOUT;
        }
        if (m.contains("Parameter: redirect_uri")) {
            return Kind.REDIRECT;
        }
        final String clientId = request.getParameter("client_id");
        if ((m.contains("Parameter: client_id") || m.startsWith("[invalid_client]") || m.startsWith("[unauthorized_client]"))
                && clientId != null && !clientId.isBlank()) {
            return Kind.CLIENT;
        }
        return Kind.REQUEST;
    }

    /** The standard error code at the start of {@code message} ({@code [invalid_request] …}), or null. */
    static String code(final String message) {
        if (message == null || !message.startsWith("[")) {
            return null;
        }
        final int end = message.indexOf(']');
        if (end < 2) {
            return null;
        }
        final String code = message.substring(1, end).toLowerCase(Locale.ROOT);
        return CODES.contains(code) ? code : null;
    }

    /** Whether the client asked for an HTML page (a browser navigation). */
    static boolean wantsHtml(final HttpServletRequest request) {
        final String accept = request.getHeader("Accept");
        return accept != null && accept.toLowerCase(Locale.ROOT).contains("text/html");
    }

    /** Holds back a 4xx {@code sendError} so the filter can render the page instead. */
    private static final class CapturingResponse extends HttpServletResponseWrapper {

        private int status;
        private String message;

        CapturingResponse(final HttpServletResponse response) {
            super(response);
        }

        @Override
        public void sendError(final int sc) throws IOException {
            sendError(sc, null);
        }

        @Override
        public void sendError(final int sc, final String msg) throws IOException {
            if (sc >= 400 && sc < 500 && status == 0 && !isCommitted()) {
                status = sc;
                message = msg;
                return;
            }
            super.sendError(sc, msg);
        }
    }
}
