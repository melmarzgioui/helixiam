/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.net;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The OIDC issuer, redirects and every absolute URL are derived from the request's host. Outside the {@code dev}
 * profile, a request whose host — after {@link TrustedProxyForwardedHeaderFilter}, so a trusted proxy's
 * {@code X-Forwarded-Host}, else the {@code Host} header — is not one of this server's is refused with {@code 400}
 * before anything is built from it. This server's hosts are those of {@code IDP_BASE_URL} and {@code SP_BASE_URL}
 * (the console proxies with its own host) plus {@code HELIX_ALLOWED_HOSTS}; the port is not compared.
 *
 * <p>Probes keep working: the host may also be the IP address the connection arrived on (a kubelet {@code httpGet}
 * probe sends the pod IP, Docker's {@code HEALTHCHECK} curls {@code 127.0.0.1}), {@code localhost} from a loopback
 * peer, and {@code /actuator/health/**} answers whatever the host (it builds no URL).
 *
 * <p>It also reports, at most once a minute, an https {@code IDP_BASE_URL} served over plain http — a TLS-terminating
 * proxy that is not listed in {@code HELIX_TRUSTED_PROXIES}, so issuers and redirects come out as {@code http://}.
 */
public class HostAllowListFilter extends OncePerRequestFilter {

    private static final Logger LOG = LogManager.getLogger(HostAllowListFilter.class);
    private static final Duration SCHEME_ERROR_INTERVAL = Duration.ofMinutes(1);

    private final Set<String> allowedHosts;
    private final boolean enforce;
    private final boolean idpHttps;
    private final Clock clock;
    private final AtomicReference<Instant> lastSchemeError = new AtomicReference<>(Instant.MIN);
    private final AtomicInteger schemeErrors = new AtomicInteger();

    HostAllowListFilter(final Set<String> allowedHosts, final boolean enforce, final boolean idpHttps, final Clock clock) {
        this.allowedHosts = Set.copyOf(allowedHosts);
        this.enforce = enforce;
        this.idpHttps = idpHttps;
        this.clock = clock;
    }

    /**
     * @param idpBaseUrl   {@code IDP_BASE_URL}
     * @param spBaseUrl    {@code SP_BASE_URL}
     * @param allowedHosts {@code HELIX_ALLOWED_HOSTS}: comma-separated host names
     * @param enforce      false in the dev profile
     */
    public static HostAllowListFilter of(final String idpBaseUrl, final String spBaseUrl, final String allowedHosts,
                                         final boolean enforce, final Clock clock) {
        final Set<String> hosts = new HashSet<>();
        addHostOf(hosts, idpBaseUrl);
        addHostOf(hosts, spBaseUrl);
        if (allowedHosts != null) {
            for (final String entry : allowedHosts.split(",")) {
                if (!entry.isBlank()) {
                    hosts.add(entry.trim().toLowerCase(Locale.ROOT));
                }
            }
        }
        final boolean idpHttps = idpBaseUrl != null && idpBaseUrl.trim().toLowerCase(Locale.ROOT).startsWith("https://");
        return new HostAllowListFilter(hosts, enforce, idpHttps, clock);
    }

    private static void addHostOf(final Set<String> hosts, final String url) {
        if (url == null || url.isBlank()) {
            return;
        }
        try {
            final String host = URI.create(url.trim()).getHost();
            if (host != null) {
                hosts.add(host.toLowerCase(Locale.ROOT));
            }
        } catch (final IllegalArgumentException e) {
            LOG.warn("Not a URL, ignored for the Host allow-list: {}", url);
        }
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
                                    final FilterChain chain) throws ServletException, IOException {
        if (!enforce) {
            chain.doFilter(request, response);
            return;
        }
        final String host = hostOf(request);
        if (allowedHosts.contains(host)) {
            reportPlainHttp(request);
            chain.doFilter(request, response);
            return;
        }
        if (isProbe(request, host)) {
            chain.doFilter(request, response);
            return;
        }
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        response.setContentType("text/plain;charset=UTF-8");
        response.getWriter().write("Unknown host.");
    }

    private static String hostOf(final HttpServletRequest request) {
        String host = request.getServerName() == null ? "" : request.getServerName().trim().toLowerCase(Locale.ROOT);
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        return host;
    }

    /** The connection's own address, {@code localhost} from a loopback peer, or a health endpoint. */
    private static boolean isProbe(final HttpServletRequest request, final String host) {
        final String path = request.getRequestURI() == null ? "" : request.getRequestURI();
        if (path.equals("/actuator/health") || path.startsWith("/actuator/health/")) {
            return true;
        }
        final InetAddress peer = ClientIpResolver.parseLiteral(ClientIpResolver.containerPeer(request));
        if ("localhost".equals(host)) {
            return peer != null && peer.isLoopbackAddress();
        }
        final InetAddress asIp = ClientIpResolver.parseLiteral(host);
        final InetAddress local = ClientIpResolver.parseLiteral(request.getLocalAddr());
        return asIp != null && local != null && asIp.equals(local);
    }

    private void reportPlainHttp(final HttpServletRequest request) {
        if (!idpHttps || request.isSecure()) {
            return;
        }
        final Instant now = clock.instant();
        final Instant last = lastSchemeError.get();
        if (now.isBefore(last.plus(SCHEME_ERROR_INTERVAL)) || !lastSchemeError.compareAndSet(last, now)) {
            return;
        }
        schemeErrors.incrementAndGet();
        LOG.error("IDP_BASE_URL is https, but this request reached the server as plain http: issuers and redirects "
                + "derived from it come out as http://. If TLS ends at a reverse proxy or load balancer, set "
                + "HELIX_TRUSTED_PROXIES to the addresses it connects from so its X-Forwarded-Proto is honoured.");
    }

    /** How many plain-http ERRORs were logged (rate-limited to one a minute). */
    int schemeErrorsLogged() {
        return schemeErrors.get();
    }
}
