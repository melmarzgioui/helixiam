/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.fapi;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Helix IAM B11 (FAPI / RFC 9101 — JWT-Secured Authorization Request, "JAR"): when a client sends a
 * {@code request} parameter (a Request Object JWT), verify its signature against the client's registered
 * JWKS and merge its claims into the authorization request the server processes. When a client is
 * configured to <em>require</em> a signed Request Object, reject a plain authorization request. No-op (the
 * request is untouched) when the client neither requires nor sends a Request Object, so the default OAuth
 * flow is unchanged. Mirrors the {@code invalid_target} JSON-error style of the Resource Indicators filter.
 */
public class RequestObjectAuthorizeFilter extends OncePerRequestFilter {

    private static final Logger LOG = LogManager.getLogger(RequestObjectAuthorizeFilter.class);

    private final RegisteredClientRepository clients;

    public RequestObjectAuthorizeFilter(final RegisteredClientRepository clients) {
        this.clients = clients;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
                                    final FilterChain chain) throws ServletException, IOException {
        final RegisteredClient client = resolveClient(request);
        if (client == null) {
            chain.doFilter(request, response);
            return;
        }
        final String requestObject = request.getParameter("request");
        final boolean requiresSigned = Boolean.TRUE.equals(
                client.getClientSettings().getSetting("helix.jar.require_signed_request_object"));

        if ((requestObject == null || requestObject.isBlank())) {
            if (requiresSigned && request.getParameter("request_uri") == null) {
                error(response, "invalid_request", "This client requires a signed request object (FAPI/JAR).");
                return;
            }
            chain.doFilter(request, response);
            return;
        }

        final Map<String, String> jarParams;
        try {
            jarParams = verifyAndExtract(requestObject, client);
        } catch (final Exception e) {
            LOG.info("Rejected request object for client {}: {}", client.getClientId(), e.getMessage());
            error(response, "invalid_request_object", "The request object could not be verified.");
            return;
        }
        chain.doFilter(new MergedParameterRequest(request, jarParams), response);
    }

    private RegisteredClient resolveClient(final HttpServletRequest request) {
        final String clientId = request.getParameter("client_id");
        if (clientId == null || clientId.isBlank()) {
            return null;
        }
        try {
            return clients.findByClientId(clientId);
        } catch (final RuntimeException e) {
            return null;
        }
    }

    /** Verifies the Request Object's signature against the client's JWKS and returns its OAuth parameters. */
    private Map<String, String> verifyAndExtract(final String requestObject, final RegisteredClient client) throws Exception {
        final String jwksUrl = client.getClientSettings().getJwkSetUrl();
        if (jwksUrl == null || jwksUrl.isBlank()) {
            throw new IllegalStateException("client has no registered JWKS to verify the request object");
        }
        final SignedJWT jwt = SignedJWT.parse(requestObject);
        final DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        final JWKSource<SecurityContext> keys = new RemoteJWKSet<>(new URL(jwksUrl));
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, keys));
        final JWTClaimsSet claims = processor.process(jwt, null);
        return RequestObject.toParameters(claims);
    }

    private static void error(final HttpServletResponse response, final String error, final String description) throws IOException {
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"" + error + "\",\"error_description\":\"" + description + "\"}");
    }

    /** Overlays the Request Object's parameters onto the servlet request so the SAS authorize endpoint sees them. */
    private static final class MergedParameterRequest extends HttpServletRequestWrapper {
        private final Map<String, String[]> merged;

        MergedParameterRequest(final HttpServletRequest request, final Map<String, String> overlay) {
            super(request);
            this.merged = new HashMap<>(request.getParameterMap());
            overlay.forEach((k, v) -> merged.put(k, new String[]{v}));
        }

        @Override
        public String getParameter(final String name) {
            final String[] values = merged.get(name);
            return values != null && values.length > 0 ? values[0] : null;
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            return Collections.unmodifiableMap(merged);
        }

        @Override
        public java.util.Enumeration<String> getParameterNames() {
            return Collections.enumeration(merged.keySet());
        }

        @Override
        public String[] getParameterValues(final String name) {
            return merged.get(name);
        }
    }
}
