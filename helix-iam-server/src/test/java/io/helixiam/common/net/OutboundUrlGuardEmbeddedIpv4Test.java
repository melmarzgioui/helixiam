/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * SSRF: an IPv6 address that embeds a blocked IPv4 address (IPv4-mapped {@code ::ffff:0:0/96}, IPv4-compatible
 * {@code ::/96}, NAT64 {@code 64:ff9b::/96}, 6to4 {@code 2002::/16}) is as blocked as the IPv4 address itself, and the
 * remaining reserved IPv4 ranges and the AWS IPv6 metadata address are blocked. Addresses come from the resolver seam
 * as {@link Inet6Address} objects (what a hostile AAAA answer gives), so the JDK's own mapped-to-IPv4 conversion of
 * literals does not hide the case.
 */
class OutboundUrlGuardEmbeddedIpv4Test {

    private static InetAddress v6(final String literal) {
        try {
            final byte[] bytes = InetAddress.getByName(literal).getAddress();
            final byte[] sixteen;
            if (bytes.length == 4) { // the JDK turned ::ffff:a.b.c.d into an Inet4Address: rebuild the mapped form
                sixteen = new byte[16];
                sixteen[10] = (byte) 0xff;
                sixteen[11] = (byte) 0xff;
                System.arraycopy(bytes, 0, sixteen, 12, 4);
            } else {
                sixteen = bytes;
            }
            return Inet6Address.getByAddress("evil.example", sixteen, -1);
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static InetAddress v4(final String literal) {
        try {
            return InetAddress.getByAddress("evil.example", InetAddress.getByName(literal).getAddress());
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static OutboundUrlGuard answering(final InetAddress address, final String... allowlist) {
        return new OutboundUrlGuard(false, List.of(allowlist), host -> new InetAddress[] {address});
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1", "::ffff:192.168.1.1", "::ffff:0.0.0.0",
        "::ffff:100.64.0.1", "::127.0.0.1", "::169.254.169.254", "::10.1.2.3",
        "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::a00:1",
        "2002:7f00:1::", "2002:a9fe:a9fe::1", "2002:c0a8:101::",
        "fd00:ec2::254"})
    void anIpv6AddressEmbeddingABlockedIpv4AddressIsRefused(final String literal) {
        final OutboundUrlGuard guard = answering(v6(literal));
        assertThatThrownBy(() -> guard.checkAllowed("https://evil.example/x")).as(literal)
                .isInstanceOf(SsrfBlockedException.class);
        assertThatThrownBy(() -> guard.resolveAllowed("https://evil.example/x")).as(literal)
                .isInstanceOf(SsrfBlockedException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"192.0.0.1", "192.0.0.170", "198.18.0.1", "198.19.255.254", "240.0.0.1",
        "250.1.2.3", "255.255.255.255"})
    void reservedIpv4RangesAreRefused(final String literal) {
        assertThat(answering(v4(literal)).isAllowed("https://evil.example/x")).as(literal).isFalse();
        assertThat(answering(v6("::ffff:" + literal)).isAllowed("https://evil.example/x")).as(literal).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::", "fd00:ec2::254",
        "::ffff:224.0.0.1", "::ffff:255.255.255.255"})
    void metadataAndBroadcastStayBlockedEvenForAnAllowlistedName(final String literal) {
        assertThat(answering(v6(literal), "evil.example").isAllowed("https://evil.example/x")).as(literal).isFalse();
    }

    @Test
    void anAllowlistedNameMayStillReachMappedLoopbackLikePlainLoopback() {
        // the allowlist lets a configured name reach loopback; the mapped spelling is the same address
        assertThat(answering(v6("::ffff:127.0.0.1"), "sidecar.local").isAllowed("http://sidecar.local/x")).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"::1", "::ffff:127.0.0.1"})
    void anAllowlistedNameResolvingToIpv6LoopbackPassesLikeIpv4Loopback(final String literal) {
        // "localhost" answers ::1 as well as 127.0.0.1: ::1 is loopback, not the IPv4-compatible 0.0.0.1
        assertThat(answering(v6(literal), "localhost").isAllowed("http://localhost/x")).as(literal).isTrue();
        assertThat(answering(v6(literal)).isAllowed("http://localhost/x")).as(literal).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"2606:4700::1111", "64:ff9b::5db8:d822", "2002:5db8:d822::1", "::ffff:93.184.216.34",
        "198.17.255.1", "198.20.0.1", "192.0.1.1", "239.255.255.254"})
    void publicAddressesStillPass(final String literal) {
        final InetAddress a = literal.contains(":") ? v6(literal) : v4(literal);
        final boolean multicast = "239.255.255.254".equals(literal);
        assertThat(answering(a).isAllowed("https://evil.example/x")).as(literal).isEqualTo(!multicast);
    }

    @Test
    void thePinnedFetcherNeverConnectsToAMappedLoopbackAddress() throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 50, InetAddress.getByName("::"))) {
            listener.setSoTimeout(300);
            final PinnedHttpFetcher fetcher = PinnedHttpFetcher.plain(answering(v6("::ffff:127.0.0.1")));
            assertThatThrownBy(() -> fetcher.get("http://evil.example:" + listener.getLocalPort() + "/m", Map.of(),
                    new PinnedHttpFetcher.Limits(Duration.ofSeconds(1), Duration.ofSeconds(2), 1000)))
                    .isInstanceOf(SsrfBlockedException.class);
            assertThatThrownBy(listener::accept).isInstanceOf(java.net.SocketTimeoutException.class);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "64:ff9b:1::7f00:1", "64:ff9b:1::a9fe:a9fe",                 // RFC 8215 local-use NAT64, /96 layout
        "64:ff9b:1:7f00:0:100::", "64:ff9b:1:a9fe:a9:fe00::",        // RFC 6052 /48 layout
        "::ffff:0:7f00:1", "::ffff:0:a9fe:a9fe",                     // SIIT ::ffff:0:0:0/96
        "2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001::1",           // Teredo 2001::/32, blocked outright
        "100::", "100::1", "100::ffff:ffff:ffff:ffff"})              // discard-only 100::/64
    void moreEmbeddedAndReservedIpv6FormsAreRefused(final String literal) {
        assertThat(answering(v6(literal)).isAllowed("https://evil.example/x")).as(literal).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"64:ff9b:1::7f00:1", "2001::1", "100::1"})
    void andStayRefusedForAnAllowlistedName(final String literal) {
        assertThat(answering(v6(literal), "evil.example").isAllowed("https://evil.example/x")).as(literal).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"2001:4860:4860::8888", "101::1"})
    void theirPublicCounterpartsStillPass(final String literal) {
        assertThat(answering(v6(literal)).isAllowed("https://evil.example/x")).as(literal).isTrue();
    }

    /** The review's GuardProbe3 cases: literal, expected blocked (for a name that is not allowlisted). */
    @ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({
        "64:ff9b:1:a9fe:a9:fe00::, true", "64:ff9b:1:12a9:fe:a9fe::, true", "64:ff9b:1:1234:a9:fea9:fe00:0, true",
        "64:ff9b:1::a9fe:a9fe, true", "64:ff9b:1:0:a:0:801:0, true", "64:ff9b:1:0:ff0a:0:8:0, true",
        "64:ff9b:1:7f00:1:0:808:808, true", "64:ff9b:1::, true", "64:ff9b:1:808:8:800::, true",
        "::ffff:0:a9fe:a9fe, true", "::ffff:0:808:808, false",
        "2001:0:4136:e378:8000:63bf:80f5:5ef6, true", "2001:1::1, false",
        "100::, true", "100::ffff:ffff:ffff:ffff, true", "100:0:0:1::1, false",
        "64:ff9b::7f00:1, true", "64:ff9b:0:0:0:1:7f00:1, true", "2002:a00:1::, true", "fc00::1, true",
        "3fff::1, true", "2001:db8::1, true", "5f00::1, true"})
    void theReviewsGuardProbe3Cases(final String literal, final boolean blocked) {
        assertThat(OutboundUrlGuard.isBlocked(v6(literal))).as(literal).isEqualTo(blocked);
    }

    @Test
    void localUseNat64IsBlockedEvenForAnAllowlistedName() {
        for (final String literal : List.of("64:ff9b:1:808:8:800::", "64:ff9b:1::5db8:d822")) {
            assertThat(OutboundUrlGuard.isAlwaysBlocked(v6(literal))).as(literal).isTrue();
        }
    }

    /** RFC 9637 documentation prefix 3fff::/20 exactly: 3fff:0000::–3fff:0fff:ffff:..., nothing beyond. */
    @ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({
        "3fff::1, true", "3fff:0fff::1, true", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff, true",
        "3fff:1000::1, false", "3fff:ffff::1, false", "3ff0::1, false", "3ffe::1, false"})
    void documentationPrefix3fffIsExactlyA20(final String literal, final boolean blocked) {
        assertThat(OutboundUrlGuard.isBlocked(v6(literal))).as(literal).isEqualTo(blocked);
    }
}
