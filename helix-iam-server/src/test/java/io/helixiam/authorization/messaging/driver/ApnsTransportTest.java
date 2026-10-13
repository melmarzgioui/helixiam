/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.driver;

import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.net.SsrfBlockedException;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * APNs requires HTTP/2, which the pinned HTTP/1.1 client does not speak (every iOS push failed). APNs is sent over the
 * JDK client with HTTP/2, no redirects, and only to Apple's two fixed hosts: a provider's {@code host} setting may name
 * one of them and nothing else.
 */
class ApnsTransportTest {

    @Test
    void theApnsClientNegotiatesHttp2AndNeverFollowsRedirects() {
        final ApnsHttp2Transport transport = new ApnsHttp2Transport(OutboundUrlGuard.blocking());
        assertThat(transport.client().version()).isEqualTo(HttpClient.Version.HTTP_2);
        assertThat(transport.client().followRedirects()).isEqualTo(HttpClient.Redirect.NEVER);
    }

    @Test
    void onlyApplesTwoHostsAreEverCalled() {
        final ApnsHttp2Transport transport = new ApnsHttp2Transport(OutboundUrlGuard.blocking());
        for (final String url : List.of("https://evil.example/3/device/t", "http://api.push.apple.com/3/device/t",
                "https://api.push.apple.com:8443/3/device/t", "https://user@api.push.apple.com/3/device/t",
                "https://api.push.apple.com.evil.example/3/device/t", "https://169.254.169.254/3/device/t")) {
            assertThatThrownBy(() -> transport.post(url, Map.of(), "{}")).as(url)
                    .isInstanceOf(SsrfBlockedException.class);
        }
        assertThat(ApnsHttp2Transport.isAppleHost("https://api.push.apple.com/3/device/t")).isTrue();
        assertThat(ApnsHttp2Transport.isAppleHost("https://api.sandbox.push.apple.com/3/device/t")).isTrue();
    }

    @Test
    void aProviderHostOutsideApplesIsAConfigurationErrorAndNothingIsSent() throws Exception {
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        final KeyPair kp = kpg.generateKeyPair();
        final String p8 = "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder().encodeToString(
                kp.getPrivate().getEncoded()) + "\n-----END PRIVATE KEY-----\n";
        final AtomicInteger sent = new AtomicInteger();
        final HttpTransport transport = (u, h, b) -> {
            sent.incrementAndGet();
            return 200;
        };
        final ResolvedProviderDto evil = new ResolvedProviderDto("PUSH", "APNS", null, null, Map.of("keyId", "K",
                "teamId", "T", "bundleId", "com.example.app", "host", "https://internal.example"), p8);
        assertThatThrownBy(() -> new ApnsPushDriver(transport).send(evil, List.of("tok"), "t", "b", Map.of()))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("host");
        assertThat(sent).hasValue(0);

        final ResolvedProviderDto sandbox = new ResolvedProviderDto("PUSH", "APNS", null, null, Map.of("keyId", "K",
                "teamId", "T", "bundleId", "com.example.app", "host", "https://api.sandbox.push.apple.com"), p8);
        new ApnsPushDriver(transport).send(sandbox, List.of("tok"), "t", "b", Map.of());
        assertThat(sent).hasValue(1);
    }
}
