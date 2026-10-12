/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.net;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletRequestWrapper;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.regex.Pattern;

/**
 * The one place that decides a request's client IP — for rate limits, audit events, risk signals and the CAPTCHA
 * {@code remoteip}. {@code X-Forwarded-For} and {@code X-Real-IP} are written by whoever sends the request, so they
 * are honoured only when the direct peer (the TCP connection) is a trusted proxy listed in
 * {@code helix.security.trusted-proxies} (comma-separated IPs or CIDR ranges, IPv4 or IPv6; default empty: no proxy
 * is trusted and the peer is the client). From a trusted peer, {@code X-Forwarded-For} is walked from the right and
 * the first address that is not a trusted proxy is the client; what lies to its left was written by the client.
 *
 * <p>The peer is read from the container's own request, underneath Spring's {@code ForwardedHeaderFilter}
 * ({@code server.forward-headers-strategy=framework}), whose wrapper reports the left-most, client-written
 * {@code X-Forwarded-For} entry as {@code getRemoteAddr()} and hides the header. Header values are only ever parsed
 * as IP literals; a host name is never looked up.
 */
@Component
public class ClientIpResolver {

    private static final Logger LOG = LogManager.getLogger(ClientIpResolver.class);

    private static final Pattern IPV4 = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");
    private static final Pattern IPV6 = Pattern.compile("[0-9A-Fa-f:.]+");

    /** The resolver for callers outside the Spring context's reach (static helpers); replaced by the bean. */
    private static volatile ClientIpResolver current = new ClientIpResolver("");

    private final List<Range> trustedProxies;

    public ClientIpResolver(@Value("${helix.security.trusted-proxies:}") final String trustedProxies) {
        final List<Range> ranges = new ArrayList<>();
        if (trustedProxies != null) {
            for (final String entry : trustedProxies.split(",")) {
                if (!entry.isBlank()) {
                    ranges.add(Range.parse(entry.trim()));
                }
            }
        }
        this.trustedProxies = List.copyOf(ranges);
    }

    /** The application's resolver (the configured bean once the context has started; else one that trusts no proxy). */
    public static ClientIpResolver current() {
        return current;
    }

    @PostConstruct
    void install() {
        current = this;
        if (!trustedProxies.isEmpty()) {
            LOG.info("Client IP: X-Forwarded-For is honoured from {} trusted proxy range(s)", trustedProxies.size());
        }
    }

    /** The client IP of {@code request}, or null without a request. */
    public String resolve(final HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        final HttpServletRequest raw = containerRequest(request);
        final String peerText = raw.getRemoteAddr();
        final InetAddress peer = parseLiteral(peerText);
        if (peer == null) {
            return peerText;
        }
        if (!isTrusted(peer)) {
            return peer.getHostAddress();
        }
        final List<String> hops = forwardedFor(raw);
        if (hops.isEmpty()) {
            final InetAddress realIp = parseLiteral(raw.getHeader("X-Real-IP"));
            return (realIp == null ? peer : realIp).getHostAddress();
        }
        InetAddress last = peer;
        for (int i = hops.size() - 1; i >= 0; i--) {
            final InetAddress hop = parseLiteral(hops.get(i));
            if (hop == null) {
                return last.getHostAddress(); // malformed: nothing to its left can be trusted
            }
            if (!isTrusted(hop)) {
                return hop.getHostAddress();
            }
            last = hop;
        }
        return last.getHostAddress(); // every hop is a trusted proxy: the left-most is the client
    }

    /** Whether any trusted proxy is configured. */
    public boolean hasTrustedProxies() {
        return !trustedProxies.isEmpty();
    }

    /** Whether the request's TCP peer (beneath any wrappers) is a trusted proxy. */
    public boolean isTrustedPeer(final HttpServletRequest request) {
        if (request == null) {
            return false;
        }
        final InetAddress peer = parseLiteral(containerRequest(request).getRemoteAddr());
        return peer != null && isTrusted(peer);
    }

    private boolean isTrusted(final InetAddress address) {
        for (final Range range : trustedProxies) {
            if (range.contains(address)) {
                return true;
            }
        }
        return false;
    }

    /** The TCP peer's address text, read from the container's request beneath any wrappers. */
    static String containerPeer(final HttpServletRequest request) {
        return containerRequest(request).getRemoteAddr();
    }

    /** The request the container created, beneath any wrappers (Spring's ForwardedHeaderFilter among them). */
    private static HttpServletRequest containerRequest(final HttpServletRequest request) {
        ServletRequest current = request;
        while (current instanceof ServletRequestWrapper wrapper) {
            current = wrapper.getRequest();
        }
        return current instanceof HttpServletRequest http ? http : request;
    }

    /** Every non-blank entry of every {@code X-Forwarded-For} header line, in order. */
    private static List<String> forwardedFor(final HttpServletRequest request) {
        final Enumeration<String> lines = request.getHeaders("X-Forwarded-For");
        if (lines == null) {
            return List.of();
        }
        final List<String> hops = new ArrayList<>();
        for (final String line : Collections.list(lines)) {
            for (final String entry : line.split(",")) {
                if (!entry.isBlank()) {
                    hops.add(entry.trim());
                }
            }
        }
        return hops;
    }

    /**
     * An IP literal, optionally {@code [v6]:port} or {@code v4:port}, or null when the text is not one. Never
     * performs a DNS lookup.
     */
    static InetAddress parseLiteral(final String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        String value = text.trim();
        if (value.startsWith("[")) {
            final int end = value.indexOf(']');
            if (end < 0) {
                return null;
            }
            value = value.substring(1, end);
        } else if (value.indexOf(':') > 0 && value.indexOf(':') == value.lastIndexOf(':') && value.indexOf('.') > 0) {
            value = value.substring(0, value.indexOf(':')); // a.b.c.d:port
        }
        final int zone = value.indexOf('%');
        if (zone >= 0) {
            value = value.substring(0, zone);
        }
        try {
            if (IPV4.matcher(value).matches()) {
                final String[] parts = value.split("\\.");
                final byte[] bytes = new byte[4];
                for (int i = 0; i < 4; i++) {
                    final int octet = Integer.parseInt(parts[i]);
                    if (octet > 255) {
                        return null;
                    }
                    bytes[i] = (byte) octet;
                }
                return InetAddress.getByAddress(bytes);
            }
            if (value.indexOf(':') >= 0 && IPV6.matcher(value).matches()) {
                // Bracketed, the JDK parses it as an IPv6 literal and never falls back to a name lookup.
                return InetAddress.getByName("[" + value + "]");
            }
        } catch (final UnknownHostException | NumberFormatException e) {
            return null;
        }
        return null;
    }

    /** An address with a prefix length (CIDR); a bare address is a full-length prefix. */
    private record Range(byte[] network, int prefix) {

        static Range parse(final String entry) {
            final int slash = entry.indexOf('/');
            final InetAddress address = parseLiteral(slash < 0 ? entry : entry.substring(0, slash));
            if (address == null) {
                throw invalid(entry);
            }
            final int bits = address.getAddress().length * 8;
            int prefix = bits;
            if (slash >= 0) {
                try {
                    prefix = Integer.parseInt(entry.substring(slash + 1).trim());
                } catch (final NumberFormatException e) {
                    throw invalid(entry);
                }
                if (prefix < 0 || prefix > bits) {
                    throw invalid(entry);
                }
            }
            return new Range(address.getAddress(), prefix);
        }

        private static IllegalArgumentException invalid(final String entry) {
            return new IllegalArgumentException("helix.security.trusted-proxies: '" + entry
                    + "' is not an IP address or CIDR range");
        }

        boolean contains(final InetAddress address) {
            final byte[] candidate = address.getAddress();
            if (candidate.length != network.length) {
                return false;
            }
            final int whole = prefix / 8;
            for (int i = 0; i < whole; i++) {
                if (candidate[i] != network[i]) {
                    return false;
                }
            }
            final int rest = prefix % 8;
            if (rest == 0) {
                return true;
            }
            final int mask = 0xFF << (8 - rest) & 0xFF;
            return (candidate[whole] & mask) == (network[whole] & mask);
        }
    }
}
