/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.webhook;

import com.sun.net.httpserver.HttpServer;
import io.helixiam.authorization.amqp.webhook.WebhookConfigPublisher;
import io.helixiam.authorization.amqp.webhook.WebhookSubscriptionDto;
import io.helixiam.authorization.federation.oidc.HttpOidcTokenClient;
import io.helixiam.authorization.federation.oidc.OidcProviderConfig;
import io.helixiam.authorization.messaging.driver.HttpTransport;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.common.net.FetchLimiter;
import io.helixiam.common.net.OutboundUrlGuard;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.Mockito;
import org.springframework.beans.factory.ObjectProvider;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Outbound slots are per feature group and per realm: 16 tarpit webhooks of one realm (endpoints that accept the
 * connection and never answer) must not delay an OIDC broker token call, an OTP send, or another realm's webhooks.
 */
class OutboundIsolationTest {

    private ServerSocket tarpit;
    private final List<Socket> held = new CopyOnWriteArrayList<>();
    private HttpServer ok;
    private final List<String> okPaths = new CopyOnWriteArrayList<>();

    @BeforeEach
    void start() throws Exception {
        tarpit = new ServerSocket(0, 200, InetAddress.getByAddress(new byte[] {127, 0, 0, 1}));
        final Thread t = new Thread(() -> {
            while (!tarpit.isClosed()) {
                try {
                    held.add(tarpit.accept()); // never answers
                } catch (final java.io.IOException e) {
                    return;
                }
            }
        }, "tarpit");
        t.setDaemon(true);
        t.start();
        ok = HttpServer.create(new InetSocketAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), 0), 0);
        ok.createContext("/", exchange -> {
            try (exchange) {
                exchange.getRequestBody().readAllBytes();
                okPaths.add(exchange.getRequestURI().getPath());
                final byte[] b = "{\"error\":\"invalid_grant\"}".getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, b.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(b);
                }
            }
        });
        ok.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
        ok.start();
    }

    @AfterEach
    void stop() throws Exception {
        tarpit.close();
        for (final Socket s : held) {
            s.close();
        }
        ok.stop(0);
    }

    private String okUrl(final String path) {
        return "http://127.0.0.1:" + ok.getAddress().getPort() + path;
    }

    @SuppressWarnings("unchecked")
    private static WebhookDispatcher dispatcher(final Map<String, List<WebhookSubscriptionDto>> hooks) {
        final WebhookConfigPublisher publisher = Mockito.mock(WebhookConfigPublisher.class);
        hooks.forEach((realm, list) -> Mockito.when(publisher.active(realm)).thenReturn(list));
        final ObjectProvider<WebhookConfigPublisher> provider = Mockito.mock(ObjectProvider.class);
        Mockito.when(provider.getIfAvailable()).thenReturn(publisher);
        return new WebhookDispatcher(provider, OutboundUrlGuard.permissive());
    }

    private static AuditEvent event(final String realm) {
        return new AuditEvent("2026-10-13T00:00:00Z", "AUTHN", "AUTHN", "LOGIN", realm, "u", null, null, null,
                "SUCCESS", Map.of());
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void tarpitWebhooksOfOneRealmBlockNeitherLoginsNorOtpNorOtherRealms() throws Exception {
        final List<WebhookSubscriptionDto> tarpits = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            tarpits.add(new WebhookSubscriptionDto("a" + i, "realm-a", "slow", "http://127.0.0.1:"
                    + tarpit.getLocalPort() + "/hook" + i, null, false, "", true, 0L));
        }
        final WebhookDispatcher hooks = dispatcher(Map.of("realm-a", tarpits, "realm-b", List.of(
                new WebhookSubscriptionDto("b1", "realm-b", "fine", okUrl("/b-hook"), null, false, "", true, 0L))));
        hooks.dispatch(event("realm-a"), "{}");
        final long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        while (held.size() < FetchLimiter.forGroup(FetchLimiter.Group.OUTBOUND).perPartitionMax()
                && System.nanoTime() < until) {
            Thread.sleep(20);
        }

        // an OIDC broker token call: answered at once (the stub answers 200 without an id_token)
        long start = System.nanoTime();
        final OidcProviderConfig config = new OidcProviderConfig("acme", "ACME", "c", "s", okUrl("/authorize"),
                okUrl("/token"), okUrl("/jwks"), "https://issuer.test", List.of("openid"));
        assertThatThrownBy(() -> new HttpOidcTokenClient(OutboundUrlGuard.permissive()).exchange(config, "code",
                "https://helix/cb")).hasMessageContaining("no id_token");
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(2));

        // an OTP send
        start = System.nanoTime();
        assertThat(new HttpTransport.Default(OutboundUrlGuard.permissive()).post(okUrl("/sms"), Map.of(), "{}"))
                .isEqualTo(200);
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(2));

        // another realm's webhook
        start = System.nanoTime();
        hooks.dispatch(event("realm-b"), "{}");
        while (!okPaths.contains("/b-hook") && System.nanoTime() - start < TimeUnit.SECONDS.toNanos(4)) {
            Thread.sleep(20);
        }
        assertThat(okPaths).contains("/b-hook");
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(2));
        // and realm A never held more than its share
        assertThat(held.size()).isLessThanOrEqualTo(FetchLimiter.forGroup(FetchLimiter.Group.OUTBOUND)
                .perPartitionMax());
    }
}
