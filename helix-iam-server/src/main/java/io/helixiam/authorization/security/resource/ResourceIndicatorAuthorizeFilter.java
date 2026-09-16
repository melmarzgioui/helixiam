/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.resource;

import io.helixiam.authorization.amqp.resource.ResourceIndicatorPublisher;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Helix IAM (RFC 8707): validate the {@code resource} parameter at {@code /oauth2/authorize} and
 * {@code /oauth2/token} <b>before</b> SAS processes the request. Two checks per requested resource:
 *
 * <ol>
 *   <li>RFC 8707 §2 — each {@code resource} MUST be an absolute URI without a fragment.</li>
 *   <li>Allow-list — when the client has a configured allow-list, the resource MUST be a member.
 *       (An empty allow-list = accept any, so pre-RFC-8707 clients are untouched.)</li>
 * </ol>
 *
 * On a violation it writes the RFC-correct {@code invalid_target} as a JSON OAuth error response
 * ({@code 400}) directly — it does NOT throw (which on this chain would dispatch to {@code /error} and
 * 302-redirect to login). When no {@code resource} is present the request passes straight through, so
 * the default OAuth token flow is byte-for-byte unchanged.
 *
 * <p>Wiring (reported, not applied — see SecurityConfig delta): add on the authorization-server chain
 * right after {@code SecurityContextHolderFilter} (alongside the existing prompt/max_age filter).
 */
public class ResourceIndicatorAuthorizeFilter extends OncePerRequestFilter {

    private static final Logger LOG = LogManager.getLogger(ResourceIndicatorAuthorizeFilter.class);
    private static final String AUTHORIZE_PATH = "/oauth2/authorize";
    private static final String TOKEN_PATH = "/oauth2/token";
    private static final String RESOURCE_PARAM = "resource";

    private final ResourceIndicatorPublisher resourcePublisher;

    public ResourceIndicatorAuthorizeFilter(final ResourceIndicatorPublisher resourcePublisher) {
        this.resourcePublisher = resourcePublisher;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
                                    final FilterChain chain) throws ServletException, IOException {
        final String path = request.getServletPath();
        if (!path.endsWith(AUTHORIZE_PATH) && !path.endsWith(TOKEN_PATH)) {
            chain.doFilter(request, response);
            return;
        }

        final List<String> requested = requestedResources(request);
        if (requested.isEmpty()) {
            // No resource indicator → default audience path. UNCHANGED.
            chain.doFilter(request, response);
            return;
        }

        // First reject malformed resources without any lookup (RFC 8707 §2).
        for (final String resource : requested) {
            if (!ResourceIndicators.isValidResource(resource)) {
                writeInvalidTarget(response, "resource must be an absolute URI without a fragment");
                return;
            }
        }

        // Then enforce the client allow-list (best-effort; a lookup failure = no allow-list = accept any).
        final List<String> allowList = resolveAllowList(request);
        if (!allowList.isEmpty()) {
            for (final String resource : requested) {
                if (!ResourceIndicators.isAllowed(resource, allowList)) {
                    writeInvalidTarget(response, "requested resource is not in the client's allowed resources");
                    return;
                }
            }
        }

        chain.doFilter(request, response);
    }

    /** All {@code resource} request parameters (the parameter MAY appear multiple times per RFC 8707). */
    private static List<String> requestedResources(final HttpServletRequest request) {
        final String[] values = request.getParameterValues(RESOURCE_PARAM);
        if (values == null || values.length == 0) {
            return Collections.emptyList();
        }
        final List<String> out = new ArrayList<>();
        for (final String v : values) {
            if (v != null && !v.isBlank()) {
                out.add(v);
            }
        }
        return out;
    }

    /** The requesting client's allow-list (empty on any failure = accept any). Resolved by client_id. */
    private List<String> resolveAllowList(final HttpServletRequest request) {
        final String clientId = clientId(request);
        if (clientId == null || clientId.isBlank()) {
            return Collections.emptyList();
        }
        try {
            final List<String> allowed = resourcePublisher.allowedResourcesForClient(
                    io.helixiam.authorization.support.RealmScopedKey.pack(
                            io.helixiam.authorization.security.realm.RealmContextHolder.get(), clientId));
            return allowed != null ? allowed : Collections.emptyList();
        } catch (final Exception e) {
            LOG.warn("Allowed-resource lookup failed for client {}, treating as no allow-list: {}",
                    clientId, e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Resolve the client id from the request: the {@code client_id} parameter ({@code /oauth2/authorize}
     * and public-client token requests), else HTTP Basic for confidential token requests.
     */
    private static String clientId(final HttpServletRequest request) {
        final String param = request.getParameter("client_id");
        if (param != null && !param.isBlank()) {
            return param;
        }
        final String auth = request.getHeader("Authorization");
        if (auth != null && auth.regionMatches(true, 0, "Basic ", 0, 6)) {
            try {
                final String decoded = new String(java.util.Base64.getDecoder()
                        .decode(auth.substring(6).trim()), java.nio.charset.StandardCharsets.UTF_8);
                final int colon = decoded.indexOf(':');
                return colon >= 0 ? decoded.substring(0, colon) : decoded;
            } catch (final IllegalArgumentException ignored) {
                return null;
            }
        }
        return null;
    }

    /** Write the RFC 6749 / RFC 8707 {@code invalid_target} error as a JSON OAuth error (400) — never a redirect. */
    private static void writeInvalidTarget(final HttpServletResponse response, final String description)
            throws IOException {
        response.setStatus(HttpStatus.BAD_REQUEST.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        final String body = "{\"error\":\"invalid_target\",\"error_description\":\""
                + description.replace("\"", "'") + "\"}";
        response.getWriter().write(body);
        response.getWriter().flush();
    }
}
