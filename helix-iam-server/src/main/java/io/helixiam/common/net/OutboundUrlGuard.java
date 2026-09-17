/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;

/**
 * Helix IAM M6 (SSRF): the single gate every server-initiated call to an <b>attacker-configurable</b> URL
 * (webhook / SCIM target / OIDC-broker token &amp; JWKS URIs / DCR client JWKS / WIF {@code jwksUri} /
 * eID artifact-resolution service / upstream &amp; back-channel logout / realm-config'd notification HTTP
 * endpoints) passes through before opening a connection. It rejects a URL whose:
 * <ul>
 *   <li>scheme is not {@code http} or {@code https} (blocks {@code file:}, {@code gopher:}, {@code ftp:}, …);</li>
 *   <li>host cannot be resolved; or</li>
 *   <li>any resolved {@link InetAddress} is loopback, wildcard ({@code 0.0.0.0} / {@code ::}), link-local
 *       ({@code 169.254.0.0/16}, {@code fe80::/10} — this covers the {@code 169.254.169.254} cloud-metadata
 *       endpoint), site-local / private ({@code 10/8}, {@code 172.16/12}, {@code 192.168/16}, {@code fc00::/7}),
 *       or multicast.</li>
 * </ul>
 *
 * <p><b>Dev escape hatch:</b> {@code helix.egress.allow-private=true} (bound from {@code HELIX_EGRESS_ALLOW_PRIVATE},
 * default {@code false}) skips the address checks so a developer can point a webhook at {@code localhost}. It is
 * <b>LOCAL DEV ONLY</b>; production keeps the secure default. The scheme check is always enforced.
 *
 * <p><b>DNS-rebinding / TOCTOU:</b> the guard resolves the host and validates <em>every</em> returned address
 * immediately before the caller connects; the JDK {@code HttpClient} then re-resolves, so a hostile resolver
 * could in theory answer differently the second time. Full elimination would require pinning the connection to
 * the validated {@code InetAddress}, which is too invasive for the shared JDK clients here — the residual window
 * is documented in the M6 report. Resolving-and-checking right before each request is the accepted mitigation.
 */
@Component
public class OutboundUrlGuard {

    private static final Logger LOG = LogManager.getLogger(OutboundUrlGuard.class);

    /** Seam over name resolution so unit tests can drive rebinding / resolution scenarios deterministically. */
    interface HostResolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    private final boolean allowPrivate;
    private final HostResolver resolver;

    /** Production bean: {@code allowPrivate} bound from {@code helix.egress.allow-private} (default false). */
    @Autowired
    public OutboundUrlGuard(@Value("${helix.egress.allow-private:false}") final boolean allowPrivate) {
        this(allowPrivate, InetAddress::getAllByName);
    }

    /**
     * Secure default for the few non-bean {@code new}-constructed seams (the FAPI request-object filter wired in
     * {@code SecurityConfig}, and the per-provider upstream-logout client). Reads {@code HELIX_EGRESS_ALLOW_PRIVATE}
     * (env or system property) so a dev container can still relax it; absent/blank ⇒ block-private (secure).
     */
    public OutboundUrlGuard() {
        this(allowPrivateFromEnvironment(), InetAddress::getAllByName);
    }

    OutboundUrlGuard(final boolean allowPrivate, final HostResolver resolver) {
        this.allowPrivate = allowPrivate;
        this.resolver = resolver;
    }

    /** A guard that permits everything with a resolvable host (tests / trusted internal wiring only). */
    public static OutboundUrlGuard permissive() {
        return new OutboundUrlGuard(true, InetAddress::getAllByName);
    }

    /** A guard that always enforces the block-private policy (tests). */
    public static OutboundUrlGuard blocking() {
        return new OutboundUrlGuard(false, InetAddress::getAllByName);
    }

    /** True when the URL is safe to fetch under the current policy; never throws. */
    public boolean isAllowed(final String url) {
        try {
            checkAllowed(url);
            return true;
        } catch (final SsrfBlockedException e) {
            return false;
        }
    }

    /**
     * Validate {@code url} for outbound use.
     *
     * @throws SsrfBlockedException when the scheme is not http/https, the host is missing/unresolvable, or any
     *                              resolved address is loopback / wildcard / link-local / private / multicast
     *                              (unless {@code allow-private} is enabled, which skips only the address checks).
     */
    public void checkAllowed(final String url) throws SsrfBlockedException {
        if (url == null || url.isBlank()) {
            throw new SsrfBlockedException("Outbound URL is missing");
        }
        final URI uri;
        try {
            uri = new URI(url.trim());
        } catch (final URISyntaxException e) {
            throw new SsrfBlockedException("Outbound URL is malformed: " + safe(url), e);
        }
        final String scheme = uri.getScheme();
        if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
            throw new SsrfBlockedException("Outbound URL scheme not allowed (only http/https): " + safe(url));
        }
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new SsrfBlockedException("Outbound URL has no resolvable host: " + safe(url));
        }
        // URI.getHost() returns IPv6 literals bracketed ("[::1]"); strip them for name resolution.
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        if (allowPrivate) {
            return; // DEV escape hatch: scheme still enforced above, address checks skipped
        }
        final InetAddress[] addresses;
        try {
            addresses = resolver.resolve(host);
        } catch (final UnknownHostException e) {
            throw new SsrfBlockedException("Outbound host could not be resolved: " + host, e);
        }
        if (addresses == null || addresses.length == 0) {
            throw new SsrfBlockedException("Outbound host resolved to no address: " + host);
        }
        for (final InetAddress address : addresses) {
            if (isBlocked(address)) {
                LOG.warn("Blocked SSRF-risky outbound URL {} → {} (internal/reserved address)", safe(url),
                        address.getHostAddress());
                throw new SsrfBlockedException("Outbound host " + host + " resolves to a blocked ("
                        + "internal/reserved) address: " + address.getHostAddress());
            }
        }
    }

    /** True for any address that must never be reachable via a user-configurable URL. */
    private static boolean isBlocked(final InetAddress address) {
        return address.isLoopbackAddress()      // 127.0.0.0/8, ::1
                || address.isAnyLocalAddress()   // 0.0.0.0, ::
                || address.isLinkLocalAddress()  // 169.254.0.0/16 (incl. metadata 169.254.169.254), fe80::/10
                || address.isSiteLocalAddress()  // 10/8, 172.16/12, 192.168/16
                || address.isMulticastAddress()  // 224/4, ff00::/8
                || isUniqueLocalIpv6(address);   // fc00::/7 (IPv6 ULA — not covered by isSiteLocalAddress)
    }

    /** IPv6 unique-local addresses ({@code fc00::/7}); the JDK's {@code isSiteLocalAddress()} is IPv4-only. */
    private static boolean isUniqueLocalIpv6(final InetAddress address) {
        final byte[] bytes = address.getAddress();
        return bytes.length == 16 && (bytes[0] & 0xFE) == 0xFC;
    }

    private static boolean allowPrivateFromEnvironment() {
        final String env = System.getenv("HELIX_EGRESS_ALLOW_PRIVATE");
        if (env != null && !env.isBlank()) {
            return Boolean.parseBoolean(env.trim());
        }
        return Boolean.parseBoolean(System.getProperty("helix.egress.allow-private", "false"));
    }

    /** Truncate for logging so a huge/hostile URL can't blow up the log line. */
    private static String safe(final String url) {
        final String s = url == null ? "" : url;
        return (s.length() > 200 ? s.substring(0, 200) + "…" : s).replaceAll("[\\r\\n]", "");
    }
}
