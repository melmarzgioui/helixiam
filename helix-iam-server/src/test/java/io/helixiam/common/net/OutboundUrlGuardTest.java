/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import io.helixiam.authorization.idp.workloadidentity.WorkloadTokenVerifier;
import io.helixiam.authorization.messaging.driver.HttpTransport;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Helix IAM M6 (SSRF): the egress guard must reject outbound URLs that resolve to loopback / cloud-metadata
 * (169.254.169.254) / private ranges, reject non-http(s) schemes, allow genuinely public hosts, and honour the
 * dev-only {@code allow-private} escape hatch. Also proves a live dispatcher seam refuses an internal URL.
 */
class OutboundUrlGuardTest {

    /** Block-private policy, real name resolution (IP literals resolve to themselves — no network needed). */
    private final OutboundUrlGuard blocking = OutboundUrlGuard.blocking();

    @Test
    void blocks_loopback() {
        assertThatThrownBy(() -> blocking.checkAllowed("http://127.0.0.1"))
                .isInstanceOf(SsrfBlockedException.class);
        assertThatThrownBy(() -> blocking.checkAllowed("http://[::1]/x"))
                .isInstanceOf(SsrfBlockedException.class);
        assertThat(blocking.isAllowed("http://127.0.0.1")).isFalse();
    }

    @Test
    void blocks_cloudMetadataLinkLocal() {
        assertThatThrownBy(() -> blocking.checkAllowed("http://169.254.169.254/latest/meta-data/"))
                .isInstanceOf(SsrfBlockedException.class)
                .hasMessageContaining("169.254.169.254");
    }

    @Test
    void blocks_privateRanges() {
        assertThat(blocking.isAllowed("http://10.0.0.5")).isFalse();
        assertThat(blocking.isAllowed("http://172.16.0.9")).isFalse();
        assertThat(blocking.isAllowed("http://192.168.1.10")).isFalse();
        assertThat(blocking.isAllowed("http://[fc00::1]/")).isFalse(); // IPv6 unique-local
    }

    @Test
    void blocks_nonHttpSchemes() {
        assertThatThrownBy(() -> blocking.checkAllowed("file:///etc/passwd"))
                .isInstanceOf(SsrfBlockedException.class);
        assertThat(blocking.isAllowed("gopher://127.0.0.1")).isFalse();
        assertThat(blocking.isAllowed("ftp://example.com/x")).isFalse();
    }

    @Test
    void blocks_blankOrMalformed() {
        assertThat(blocking.isAllowed(null)).isFalse();
        assertThat(blocking.isAllowed("   ")).isFalse();
        assertThat(blocking.isAllowed("http://")).isFalse(); // no host
    }

    @Test
    void allows_publicHost() {
        // Inject a resolver that maps the hostname to a public IP so the test needs no live DNS.
        final OutboundUrlGuard guard = new OutboundUrlGuard(false,
                host -> new InetAddress[]{InetAddress.getByName("93.184.216.34")}); // example.com
        assertThatCode(() -> guard.checkAllowed("https://example.com/webhook")).doesNotThrowAnyException();
        assertThat(guard.isAllowed("https://example.com/webhook")).isTrue();
    }

    @Test
    void dnsRebinding_blockedWhenAnyResolvedAddressIsInternal() {
        // A hostile resolver returning a public AND a private address must still be rejected.
        final OutboundUrlGuard guard = new OutboundUrlGuard(false, host -> new InetAddress[]{
                InetAddress.getByName("93.184.216.34"),
                InetAddress.getByName("169.254.169.254")});
        assertThat(guard.isAllowed("http://rebind.example.com/")).isFalse();
    }

    @Test
    void allowPrivateEscapeHatch_skipsAddressChecksButKeepsSchemeCheck() {
        final OutboundUrlGuard permissive = new OutboundUrlGuard(true); // dev-only
        assertThatCode(() -> permissive.checkAllowed("http://127.0.0.1:9000/hook")).doesNotThrowAnyException();
        assertThatCode(() -> permissive.checkAllowed("http://169.254.169.254/")).doesNotThrowAnyException();
        // Scheme is still enforced even with the escape hatch on.
        assertThatThrownBy(() -> permissive.checkAllowed("file:///etc/passwd"))
                .isInstanceOf(SsrfBlockedException.class);
    }

    // ---- Dispatcher-level enforcement (proves the guard is actually wired into an outbound seam) ----

    @Test
    void httpTransportDispatcher_refusesInternalUrl() {
        final HttpTransport.Default transport = new HttpTransport.Default(OutboundUrlGuard.blocking());
        assertThatThrownBy(() -> transport.post("http://169.254.169.254/send", Map.of(), "{}"))
                .isInstanceOf(SsrfBlockedException.class);
    }

    @Test
    void workloadTokenVerifier_refusesInternalJwksUri() {
        final WorkloadTokenVerifier verifier = new WorkloadTokenVerifier(OutboundUrlGuard.blocking());
        assertThatThrownBy(() -> verifier.jwkSource("http://169.254.169.254/jwks"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Blocked JWKS URI");
    }
}
