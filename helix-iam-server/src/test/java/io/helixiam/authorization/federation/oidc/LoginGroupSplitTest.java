/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.oidc;

import com.sun.net.httpserver.HttpServer;
import io.helixiam.common.net.FetchLimiter;
import io.helixiam.common.net.OutboundUrlGuard;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Client-controlled login fetches (client-assertion and request-object JWKS: anyone can register a client through open
 * DCR) and admin-configured ones (OIDC broker, eID, WIF) have separate slots: clients that hold every client slot
 * cannot delay a broker login.
 */
class LoginGroupSplitTest {

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void exhaustedClientSlotsDoNotDelayABrokerLogin() throws Exception {
        final FetchLimiter clients = FetchLimiter.forGroup(FetchLimiter.Group.LOGIN_CLIENT);
        assertThat(clients).isNotSameAs(FetchLimiter.forGroup(FetchLimiter.Group.LOGIN_ADMIN));
        final Method acquire = FetchLimiter.class.getDeclaredMethod("acquire", long.class, String.class);
        final Method release = FetchLimiter.class.getDeclaredMethod("release", String.class);
        acquire.setAccessible(true);
        release.setAccessible(true);
        final int slots = clients.max();
        for (int i = 0; i < slots; i++) {
            assertThat((Boolean) acquire.invoke(clients, System.nanoTime() + 1_000_000_000L, "dcr-" + i)).isTrue();
        }
        final HttpServer op = HttpServer.create(new InetSocketAddress(InetAddress.getByAddress(
                new byte[] {127, 0, 0, 1}), 0), 0);
        op.createContext("/", x -> {
            final byte[] b = "{\"access_token\":\"at\"}".getBytes(StandardCharsets.UTF_8);
            x.sendResponseHeaders(200, b.length);
            x.getResponseBody().write(b);
            x.close();
        });
        op.start();
        try {
            final String base = "http://127.0.0.1:" + op.getAddress().getPort();
            final OidcProviderConfig config = new OidcProviderConfig("acme", "ACME", "c", "s", base + "/authorize",
                    base + "/token", base + "/jwks", "https://issuer.test", List.of("openid"));
            final long start = System.nanoTime();
            assertThatThrownBy(() -> new HttpOidcTokenClient(OutboundUrlGuard.permissive()).exchange(config, "code",
                    "https://helix/cb")).hasMessageContaining("no id_token");
            assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(2));
        } finally {
            op.stop(0);
            for (int i = 0; i < slots; i++) {
                release.invoke(clients, "dcr-" + i);
            }
        }
    }
}
