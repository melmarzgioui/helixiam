/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import io.helixiam.common.log.LogSafe;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Outbound policy for admin-configured LDAP directories. A directory on a public address is always allowed (subject to
 * the usual reserved-range checks). A directory on a private or loopback address is allowed only when the deployment
 * lists it in {@code helix.federation.ldap.allowed-hosts}: by host name ({@code ldap.corp}, {@code ldap.corp:636}) or
 * by address range ({@code 10.20.0.0/16}). A realm administrator can type any URL, but cannot widen this list.
 * Cloud metadata, link-local, multicast and the other always-blocked addresses stay refused even when a listed name or
 * range covers them. The host is resolved once and the caller connects to the returned address.
 */
public final class LdapEgressGuard {

    /** A validated directory: the name as configured, its port, and the addresses to connect to. */
    public record Target(String host, int port, List<InetAddress> addresses) {
        public Target {
            addresses = List.copyOf(addresses);
        }
    }

    private record Cidr(byte[] network, int prefix) {
        boolean contains(final InetAddress address) {
            final byte[] a = address.getAddress();
            if (a.length != network.length) {
                return false;
            }
            int bits = prefix;
            for (int i = 0; i < a.length && bits > 0; i++, bits -= 8) {
                final int mask = bits >= 8 ? 0xff : (0xff << (8 - bits)) & 0xff;
                if ((a[i] & mask) != (network[i] & mask)) {
                    return false;
                }
            }
            return true;
        }
    }

    private final List<String> names;
    private final List<Cidr> ranges;
    private final OutboundUrlGuard.HostResolver resolver;

    public LdapEgressGuard(final String allowedHosts) {
        this(allowedHosts, InetAddress::getAllByName);
    }

    public LdapEgressGuard(final String allowedHosts, final OutboundUrlGuard.HostResolver resolver) {
        final List<String> n = new ArrayList<>();
        final List<Cidr> r = new ArrayList<>();
        if (allowedHosts != null) {
            for (final String raw : allowedHosts.split(",")) {
                final String entry = raw.trim().toLowerCase(Locale.ROOT);
                if (entry.isEmpty()) {
                    continue;
                }
                if (entry.contains("/")) {
                    final Cidr cidr = parseCidr(entry);
                    if (cidr == null) {
                        throw new IllegalArgumentException("helix.federation.ldap.allowed-hosts: invalid range '"
                                + LogSafe.sanitize(entry) + "'");
                    }
                    r.add(cidr);
                } else {
                    n.add(entry);
                }
            }
        }
        this.names = OutboundUrlGuard.parseAllowlist(String.join(",", n));
        this.ranges = List.copyOf(r);
        this.resolver = resolver;
    }

    /** True when the deployment listed at least one host or range. */
    public boolean hasAllowlist() {
        return !names.isEmpty() || !ranges.isEmpty();
    }

    /**
     * Resolves {@code host} once and checks every address.
     *
     * @throws UnresolvableHostException when the name does not resolve
     * @throws SsrfBlockedException      when an address is not allowed
     */
    public Target resolve(final String host, final int port) throws SsrfBlockedException {
        if (host == null || host.isBlank() || port < 1 || port > 65535) {
            throw new SsrfBlockedException("LDAP host or port is missing");
        }
        final String h = host.trim();
        final InetAddress[] addresses;
        try {
            addresses = resolver.resolve(h);
        } catch (final UnknownHostException e) {
            throw new UnresolvableHostException("LDAP host could not be resolved", e);
        }
        if (addresses == null || addresses.length == 0) {
            throw new UnresolvableHostException("LDAP host resolved to no address");
        }
        final OutboundUrlGuard fixed = new OutboundUrlGuard(false, names, name -> addresses.clone());
        try {
            fixed.resolveAllowedHost(h, port);
        } catch (final UnresolvableHostException e) {
            throw e;
        } catch (final SsrfBlockedException e) {
            if (!inListedRanges(addresses)) {
                throw new SsrfBlockedException("The LDAP host is not allowed by the egress policy "
                        + "(list it in helix.federation.ldap.allowed-hosts)");
            }
        }
        return new Target(h, port, List.of(addresses));
    }

    private boolean inListedRanges(final InetAddress[] addresses) {
        if (ranges.isEmpty()) {
            return false;
        }
        for (final InetAddress address : addresses) {
            if (OutboundUrlGuard.isAlwaysBlocked(address)
                    || ranges.stream().noneMatch(range -> range.contains(address))) {
                return false;
            }
        }
        return true;
    }

    private static Cidr parseCidr(final String entry) {
        final int slash = entry.indexOf('/');
        final String ip = entry.substring(0, slash);
        // literal addresses only: never resolve a name while parsing the configuration
        if (ip.isEmpty() || !(ip.indexOf(':') >= 0 || ip.matches("[0-9.]+"))) {
            return null;
        }
        try {
            final byte[] network = InetAddress.getByName(ip).getAddress();
            final int prefix = Integer.parseInt(entry.substring(slash + 1));
            return prefix >= 0 && prefix <= network.length * 8 ? new Cidr(network, prefix) : null;
        } catch (final UnknownHostException | NumberFormatException e) {
            return null;
        }
    }
}
