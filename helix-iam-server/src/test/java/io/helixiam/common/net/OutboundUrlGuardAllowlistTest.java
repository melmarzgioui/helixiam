/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import io.helixiam.authorization.messaging.driver.HttpTransport;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * C6 (security): an explicit allowlist of private hosts ({@code helix.egress.allowed-private-hosts}) instead of the
 * all-or-nothing {@code allow-private} switch. Only the configured names (optionally with a port) may reach private
 * addresses; every other URL — including another name that resolves to the same private address, and the IP literal
 * itself — is resolved and checked as before. Link-local (cloud metadata), multicast and wildcard addresses stay
 * blocked even for an allowlisted name.
 */
class OutboundUrlGuardAllowlistTest {

    /** A fake resolver: in-cluster names resolve to private addresses, everything else to a public one. */
    private static final OutboundUrlGuard.HostResolver DNS = host -> switch (host.toLowerCase(java.util.Locale.ROOT)) {
        case "mailer.mail.svc.cluster.local", "evil.example" -> addr("10.0.0.7");
        case "sms.internal" -> addr("192.168.4.2");
        case "metadata.internal" -> addr("169.254.169.254");
        case "sidecar" -> addr("127.0.0.1");
        case "public.example" -> addr("93.184.216.34");
        default -> {
            if (!host.matches("[0-9.]+|[0-9a-fA-F:]+")) {
                throw new UnknownHostException(host); // deterministic: no real DNS in this test
            }
            yield InetAddress.getAllByName(host); // IP literals resolve to themselves
        }
    };

    private static OutboundUrlGuard guard(final String... allowed) {
        return new OutboundUrlGuard(false, List.of(allowed), DNS);
    }

    @Test
    void anAllowlistedPrivateHost_passes_andOthersAreBlocked() {
        final OutboundUrlGuard g = guard("mailer.mail.svc.cluster.local");
        assertThat(g.isAllowed("http://mailer.mail.svc.cluster.local:8025/send")).isTrue();
        assertThat(g.isAllowed("https://MAILER.mail.svc.cluster.local/send")).as("host names are case-insensitive").isTrue();
        assertThat(g.isAllowed("http://sms.internal/send")).isFalse();
        assertThat(g.isAllowed("http://127.0.0.1/")).isFalse();
        assertThat(g.isAllowed("https://public.example/hook")).isTrue();
    }

    @Test
    void theAllowlistMatchesTheConfiguredName_notTheAddressItResolvesTo() {
        final OutboundUrlGuard g = guard("mailer.mail.svc.cluster.local");
        assertThat(g.isAllowed("http://evil.example/")).as("another name for the same private address").isFalse();
        assertThat(g.isAllowed("http://10.0.0.7/")).as("the address itself").isFalse();
        assertThat(g.isAllowed("http://mailer.mail.svc.cluster.local.evil.example/")).isFalse();
        assertThat(g.isAllowed("http://mailer.mail.svc.cluster.local@evil.example/")).isFalse();
    }

    @Test
    void aHostPortEntry_allowsOnlyThatPort_withSchemeDefaults() {
        final OutboundUrlGuard g = guard("sms.internal:8080", "mailer.mail.svc.cluster.local:443");
        assertThat(g.isAllowed("http://sms.internal:8080/send")).isTrue();
        assertThat(g.isAllowed("http://sms.internal:8081/send")).isFalse();
        assertThat(g.isAllowed("http://sms.internal/send")).as("port 80").isFalse();
        assertThat(g.isAllowed("https://mailer.mail.svc.cluster.local/send")).as("https default port 443").isTrue();
        assertThat(g.isAllowed("http://mailer.mail.svc.cluster.local/send")).as("http default port 80").isFalse();
    }

    @Test
    void anIpLiteralEntry_allowsThatAddress() {
        final OutboundUrlGuard g = guard("10.0.0.7", "[fd00::5]:9000");
        assertThat(g.isAllowed("http://10.0.0.7/")).isTrue();
        assertThat(g.isAllowed("http://10.0.0.8/")).isFalse();
        assertThat(g.isAllowed("http://[fd00::5]:9000/")).isTrue();
        assertThat(g.isAllowed("http://[fd00::5]:9001/")).isFalse();
    }

    @Test
    void metadataMulticastAndWildcard_stayBlocked_evenWhenAllowlisted() {
        final OutboundUrlGuard g = guard("metadata.internal", "169.254.169.254", "0.0.0.0", "224.0.0.1");
        assertThatThrownBy(() -> g.checkAllowed("http://metadata.internal/latest/meta-data/"))
                .isInstanceOf(SsrfBlockedException.class);
        assertThat(g.isAllowed("http://169.254.169.254/")).isFalse();
        assertThat(g.isAllowed("http://0.0.0.0/")).isFalse();
        assertThat(g.isAllowed("http://224.0.0.1/")).isFalse();
    }

    @Test
    void anExplicitlyListedLoopbackName_isAllowed() {
        assertThat(guard("sidecar:9000").isAllowed("http://sidecar:9000/mail")).isTrue();
        assertThat(guard().isAllowed("http://sidecar:9000/mail")).isFalse();
    }

    @Test
    void theSchemeCheckStillApplies() {
        assertThat(guard("mailer.mail.svc.cluster.local").isAllowed("gopher://mailer.mail.svc.cluster.local/")).isFalse();
    }

    @Test
    void entriesAreParsedFromACommaSeparatedSetting_andBadEntriesAreIgnored() {
        assertThat(OutboundUrlGuard.parseAllowlist(" Mailer.svc , sms.internal:8080,, http://x/ , host:notaport , [fd00::1]:25 "))
                .containsExactly("mailer.svc", "sms.internal:8080", "[fd00::1]:25");
        assertThat(OutboundUrlGuard.parseAllowlist(null)).isEmpty();
    }

    @Test
    void theDeprecatedAllowPrivateSwitch_stillWorks() {
        final OutboundUrlGuard legacy = new OutboundUrlGuard(true, List.of(), DNS);
        assertThat(legacy.isAllowed("http://sms.internal/")).isTrue();
    }

    @Test
    void theHttpEmailAndSmsDriverTransport_honoursTheAllowlist() {
        final HttpTransport.Default transport = new HttpTransport.Default(guard("127.0.0.1:1"));
        // Allowed by the guard, so it gets as far as connecting (nothing listens there) — not an SSRF refusal.
        assertThatThrownBy(() -> transport.post("http://127.0.0.1:1/send", Map.of(), "{}"))
                .isNotInstanceOf(SsrfBlockedException.class);
        assertThatThrownBy(() -> transport.post("http://sms.internal:1/send", Map.of(), "{}"))
                .isInstanceOf(SsrfBlockedException.class);
    }

    private static InetAddress[] addr(final String ip) throws UnknownHostException {
        return new InetAddress[] {InetAddress.getByName(ip)};
    }
}
