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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The OIDC issuer, redirects and every absolute URL are derived from the request's host. Outside the {@code dev}
 * profile, a request whose host — after {@link TrustedProxyForwardedHeaderFilter}, so a trusted proxy's
 * {@code X-Forwarded-Host}, else the {@code Host} header — is not one of this server's is refused with {@code 400}
 * before anything is built from it. This server's hosts are those of {@code IDP_BASE_URL} and {@code SP_BASE_URL}
 * (the console proxies with its own host) plus {@code HELIX_ALLOWED_HOSTS}.
 *
 * <p>The port is compared too, since it is echoed into the issuer as well ({@code Host: localhost:6666} gave
 * {@code http://localhost:6666/realms/...}). A base URL's host accepts its explicit port, or the scheme's default port
 * when it names none; a {@code HELIX_ALLOWED_HOSTS} entry accepts any port unless it names one ({@code host:port},
 * {@code [v6]:port}). A request port that no URL would show (the default port of the request's own scheme, which is
 * also what a {@code Host} without a port gives) is accepted for an allowed host. A port outside 1..65535 is refused.
 *
 * <p>Probes keep working: the host may also be the IP address the connection arrived on (a kubelet {@code httpGet}
 * probe sends the pod IP, Docker's {@code HEALTHCHECK} curls {@code 127.0.0.1}) or {@code localhost} from a loopback
 * peer, on the port the connection arrived on; and {@code /actuator/health/**} answers whatever the host and port (it
 * builds no URL).
 *
 * <p>It also reports, at most once a minute, an https {@code IDP_BASE_URL} served over plain http — a TLS-terminating
 * proxy that is not listed in {@code HELIX_TRUSTED_PROXIES}, so issuers and redirects come out as {@code http://}.
 */
public class HostAllowListFilter extends OncePerRequestFilter {

    private static final Logger LOG = LogManager.getLogger(HostAllowListFilter.class);
    private static final Duration SCHEME_ERROR_INTERVAL = Duration.ofMinutes(1);

    /** A port entry that accepts every port of its host. */
    private static final int ANY_PORT = -1;
    private static final int DEFAULT_HTTP_PORT = 80;
    private static final int DEFAULT_HTTPS_PORT = 443;
    private static final int MAX_PORT = 65_535;

    /** Allowed host → the ports it accepts ({@link #ANY_PORT}: all). */
    private final Map<String, Set<Integer>> allowedHosts;
    private final boolean enforce;
    private final boolean idpHttps;
    private final Clock clock;
    private final AtomicReference<Instant> lastSchemeError = new AtomicReference<>(Instant.MIN);
    private final AtomicInteger schemeErrors = new AtomicInteger();

    HostAllowListFilter(final Map<String, Set<Integer>> allowedHosts, final boolean enforce, final boolean idpHttps,
                        final Clock clock) {
        final Map<String, Set<Integer>> copy = new HashMap<>();
        allowedHosts.forEach((host, ports) -> copy.put(host, Set.copyOf(ports)));
        this.allowedHosts = Map.copyOf(copy);
        this.enforce = enforce;
        this.idpHttps = idpHttps;
        this.clock = clock;
    }

    /**
     * @param idpBaseUrl   {@code IDP_BASE_URL}
     * @param spBaseUrl    {@code SP_BASE_URL}
     * @param allowedHosts {@code HELIX_ALLOWED_HOSTS}: comma-separated host names, each optionally with a port
     * @param enforce      false in the dev profile
     */
    public static HostAllowListFilter of(final String idpBaseUrl, final String spBaseUrl, final String allowedHosts,
                                         final boolean enforce, final Clock clock) {
        final Map<String, Set<Integer>> hosts = new HashMap<>();
        addHostOf(hosts, idpBaseUrl);
        addHostOf(hosts, spBaseUrl);
        if (allowedHosts != null) {
            for (final String entry : allowedHosts.split(",")) {
                if (!entry.isBlank()) {
                    addEntry(hosts, entry.trim().toLowerCase(Locale.ROOT));
                }
            }
        }
        final boolean idpHttps = idpBaseUrl != null && idpBaseUrl.trim().toLowerCase(Locale.ROOT).startsWith("https://");
        return new HostAllowListFilter(hosts, enforce, idpHttps, clock);
    }

    /** A base URL's host with its explicit port, or the scheme's default port when it names none. */
    private static void addHostOf(final Map<String, Set<Integer>> hosts, final String url) {
        if (url == null || url.isBlank()) {
            return;
        }
        try {
            final URI uri = URI.create(url.trim());
            final String host = uri.getHost();
            if (host != null) {
                final int port = uri.getPort() != -1 ? uri.getPort()
                        : "https".equalsIgnoreCase(uri.getScheme()) ? DEFAULT_HTTPS_PORT : DEFAULT_HTTP_PORT;
                allow(hosts, unbracket(host.toLowerCase(Locale.ROOT)), port);
            }
        } catch (final IllegalArgumentException e) {
            LOG.warn("Not a URL, ignored for the Host allow-list: {}", url);
        }
    }

    /** A {@code HELIX_ALLOWED_HOSTS} entry: {@code host}, {@code host:port}, {@code v6}, {@code [v6]} or {@code [v6]:port}. */
    private static void addEntry(final Map<String, Set<Integer>> hosts, final String entry) {
        String host = entry;
        String port = null;
        if (entry.startsWith("[")) {
            final int close = entry.indexOf(']');
            if (close < 0) {
                LOG.warn("Not a host name, ignored for the Host allow-list: {}", entry);
                return;
            }
            host = entry.substring(1, close);
            if (entry.length() > close + 1) {
                if (entry.charAt(close + 1) != ':') {
                    LOG.warn("Not a host name, ignored for the Host allow-list: {}", entry);
                    return;
                }
                port = entry.substring(close + 2);
            }
        } else if (entry.indexOf(':') >= 0 && entry.indexOf(':') == entry.lastIndexOf(':')) {
            host = entry.substring(0, entry.indexOf(':'));
            port = entry.substring(entry.indexOf(':') + 1);
        }
        if (port == null) {
            allow(hosts, host, ANY_PORT);
            return;
        }
        final int number = parsePort(port);
        if (number == -1) {
            LOG.warn("Not a valid port, ignored for the Host allow-list: {}", entry);
            return;
        }
        allow(hosts, host, number);
    }

    private static int parsePort(final String port) {
        if (port.isEmpty() || port.length() > 5 || !port.chars().allMatch(Character::isDigit)) {
            return -1;
        }
        final int number = Integer.parseInt(port);
        return number >= 1 && number <= MAX_PORT ? number : -1;
    }

    private static void allow(final Map<String, Set<Integer>> hosts, final String host, final int port) {
        hosts.computeIfAbsent(host, h -> new HashSet<>()).add(port);
    }

    private static String unbracket(final String host) {
        return host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
                                    final FilterChain chain) throws ServletException, IOException {
        if (!enforce) {
            chain.doFilter(request, response);
            return;
        }
        if (isHealth(request)) {
            chain.doFilter(request, response); // builds no URL: any host, any port
            return;
        }
        final String host = hostOf(request);
        final int port = request.getServerPort();
        final boolean validPort = port >= 1 && port <= MAX_PORT;
        if (validPort && portAllowed(allowedHosts.get(host), port, request)) {
            reportPlainHttp(request);
            chain.doFilter(request, response);
            return;
        }
        if (validPort && isProbe(request, host, port)) {
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

    /**
     * Whether an allowed host accepts this port: one it lists, any when it lists {@link #ANY_PORT}, or the default port
     * of the request's own scheme, which no built URL shows (and which a {@code Host} without a port gives).
     */
    private static boolean portAllowed(final Set<Integer> ports, final int port, final HttpServletRequest request) {
        if (ports == null) {
            return false;
        }
        return ports.contains(ANY_PORT) || ports.contains(port) || port == defaultPort(request);
    }

    private static int defaultPort(final HttpServletRequest request) {
        return "https".equalsIgnoreCase(request.getScheme()) ? DEFAULT_HTTPS_PORT : DEFAULT_HTTP_PORT;
    }

    private static boolean isHealth(final HttpServletRequest request) {
        final String path = request.getRequestURI() == null ? "" : request.getRequestURI();
        return path.equals("/actuator/health") || path.startsWith("/actuator/health/");
    }

    /**
     * A probe: the connection's own address, or {@code localhost} from a loopback peer — on the port the connection
     * arrived on (or the scheme's default, which no URL shows), so a probe exemption never echoes a chosen port.
     */
    private static boolean isProbe(final HttpServletRequest request, final String host, final int port) {
        if (port != request.getLocalPort() && port != defaultPort(request)) {
            return false;
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
