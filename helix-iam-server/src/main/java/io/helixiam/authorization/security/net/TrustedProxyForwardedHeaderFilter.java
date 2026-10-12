/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.net;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.ForwardedHeaderFilter;

import java.io.IOException;

/**
 * Spring's {@link ForwardedHeaderFilter} ({@code server.forward-headers-strategy=framework}), applied only when the
 * request's TCP peer is a trusted proxy ({@code helix.security.trusted-proxies}, via {@link ClientIpResolver}).
 * {@code Forwarded} and {@code X-Forwarded-Host/-Proto/-Port/-Prefix/-Ssl/-For} decide the scheme, host, port and
 * context path the server sees — and so {@code isSecure()}, the OIDC issuer it derives from the request and every
 * absolute URL and redirect. From any other peer they are written by the client, so they are removed and ignored.
 */
public class TrustedProxyForwardedHeaderFilter extends ForwardedHeaderFilter {

    private final ClientIpResolver clientIps;
    /** Strips the forwarded headers without applying them (for requests from untrusted peers). */
    private final ForwardedHeaderFilter remover = new ForwardedHeaderFilter();

    public TrustedProxyForwardedHeaderFilter(final ClientIpResolver clientIps) {
        this.clientIps = clientIps;
        this.remover.setRemoveOnly(true);
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
                                    final FilterChain filterChain) throws ServletException, IOException {
        if (clientIps.isTrustedPeer(request)) {
            super.doFilterInternal(request, response, filterChain);
        } else {
            remover.doFilter(request, response, filterChain);
        }
    }
}
