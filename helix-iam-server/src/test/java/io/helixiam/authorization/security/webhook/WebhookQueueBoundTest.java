/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.webhook;

import com.sun.net.httpserver.HttpServer;
import io.helixiam.authorization.amqp.webhook.WebhookConfigPublisher;
import io.helixiam.authorization.amqp.webhook.WebhookSubscriptionDto;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.net.RealmBoundedExecutor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.Mockito;
import org.springframework.beans.factory.ObjectProvider;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * One realm cannot pile up webhook deliveries: at most 1,000 are pending per realm, the rest are dropped without
 * blocking the producer, and another realm's delivery still goes out at once.
 */
class WebhookQueueBoundTest {

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    @SuppressWarnings("unchecked")
    void aRealmsPendingDeliveriesAreBoundedAndOtherRealmsAreNotDelayed() throws Exception {
        final List<Socket> held = new CopyOnWriteArrayList<>();
        try (ServerSocket tarpit = new ServerSocket(0, 1_000, InetAddress.getByAddress(new byte[] {127, 0, 0, 1}))) {
            final Thread t = new Thread(() -> {
                while (!tarpit.isClosed()) {
                    try {
                        held.add(tarpit.accept());
                    } catch (final java.io.IOException e) {
                        return;
                    }
                }
            });
            t.setDaemon(true);
            t.start();
            final HttpServer ok = HttpServer.create(new InetSocketAddress(
                    InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), 0), 0);
            final List<String> delivered = new CopyOnWriteArrayList<>();
            ok.createContext("/", x -> {
                delivered.add(x.getRequestURI().getPath());
                x.sendResponseHeaders(204, -1);
                x.close();
            });
            ok.start();
            try {
                final WebhookConfigPublisher publisher = Mockito.mock(WebhookConfigPublisher.class);
                Mockito.when(publisher.active("realm-a")).thenReturn(List.of(new WebhookSubscriptionDto("a", "realm-a",
                        "slow", "http://127.0.0.1:" + tarpit.getLocalPort() + "/hook", null, false, "", true, 0L)));
                Mockito.when(publisher.active("realm-b")).thenReturn(List.of(new WebhookSubscriptionDto("b", "realm-b",
                        "fine", "http://127.0.0.1:" + ok.getAddress().getPort() + "/b", null, false, "", true, 0L)));
                final ObjectProvider<WebhookConfigPublisher> provider = Mockito.mock(ObjectProvider.class);
                Mockito.when(provider.getIfAvailable()).thenReturn(publisher);
                final WebhookDispatcher hooks = new WebhookDispatcher(provider, OutboundUrlGuard.permissive());

                final long produce = System.nanoTime();
                for (int i = 0; i < 1_200; i++) {
                    hooks.dispatch(event("realm-a"), "{}");
                }
                assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - produce)).isLessThan(2_000);
                assertThat(hooks.queue().pending("realm-a"))
                        .isLessThanOrEqualTo(RealmBoundedExecutor.DEFAULT_MAX_PENDING_PER_REALM);
                assertThat(hooks.queue().dropped("realm-a")).isGreaterThanOrEqualTo(200);

                final long start = System.nanoTime();
                hooks.dispatch(event("realm-b"), "{}");
                while (delivered.isEmpty() && System.nanoTime() - start < TimeUnit.SECONDS.toNanos(5)) {
                    Thread.sleep(20);
                }
                assertThat(delivered).containsExactly("/b");
                assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)).isLessThan(2_000);
            } finally {
                ok.stop(0);
                for (final Socket s : held) {
                    s.close();
                }
            }
        }
    }

    private static AuditEvent event(final String realm) {
        return new AuditEvent("2026-10-13T00:00:00Z", "AUTHN", "AUTHN", "LOGIN", realm, "u", null, null, null,
                "SUCCESS", Map.of());
    }
}
