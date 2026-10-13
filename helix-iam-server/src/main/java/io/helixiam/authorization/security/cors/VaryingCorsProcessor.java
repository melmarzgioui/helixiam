/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.cors;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.Nullable;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.DefaultCorsProcessor;

import java.io.IOException;
import java.util.Collection;

/**
 * Spring Framework's {@link DefaultCorsProcessor}, with Spring Framework 6's {@code Vary} behaviour: every response
 * that passes the CORS filter varies by {@code Origin}, {@code Access-Control-Request-Method} and
 * {@code Access-Control-Request-Headers}, also when no CORS configuration applies to the request (an origin no client
 * registered, a non-CORS request). Spring Framework 7 adds them only when a configuration applies, so a shared cache
 * could serve a response without CORS headers to an origin that would have received them (or the reverse). HelixIAM
 * 1.0 sent them on every response; this keeps that. CORS decisions themselves are unchanged.
 */
public class VaryingCorsProcessor extends DefaultCorsProcessor {

    @Override
    public boolean processRequest(@Nullable final CorsConfiguration config, final HttpServletRequest request,
                                  final HttpServletResponse response) throws IOException {
        final Collection<String> vary = response.getHeaders(HttpHeaders.VARY);
        for (final String header : new String[] {HttpHeaders.ORIGIN, HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD,
                HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS}) {
            if (!vary.contains(header)) {
                response.addHeader(HttpHeaders.VARY, header);
            }
        }
        return super.processRequest(config, request, response);
    }
}
