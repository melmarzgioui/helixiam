/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.webhook;

import io.helixiam.authorization.amqp.webhook.WebhookConfigPublisher;
import io.helixiam.authorization.amqp.webhook.WebhookSubscriptionDto;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.testsupport.RebindingTarget;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.Mockito;
import org.springframework.beans.factory.ObjectProvider;

import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/** M6: a webhook POST goes to the address the guard validated, never to a second DNS answer. */
class WebhookDispatcherRebindingTest {

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    @SuppressWarnings("unchecked")
    void theWebhookIsPostedToTheValidatedAddressOnly() throws Exception {
        try (RebindingTarget target = RebindingTarget.http("hooks.rebind.test")) {
            final WebhookConfigPublisher publisher = Mockito.mock(WebhookConfigPublisher.class);
            Mockito.when(publisher.active("acme")).thenReturn(List.of(new WebhookSubscriptionDto("h1", "acme", "hook",
                    target.url("http", "/hook"), "s3cret", true, "", true, 0L)));
            final ObjectProvider<WebhookConfigPublisher> provider = Mockito.mock(ObjectProvider.class);
            Mockito.when(provider.getIfAvailable()).thenReturn(publisher);
            final WebhookDispatcher dispatcher = new WebhookDispatcher(provider, target.guard());

            final String json = "{\"type\":\"LOGIN\"}";
            dispatcher.dispatch(new AuditEvent("2026-10-13T00:00:00Z", "AUTHN", "AUTHN", "LOGIN", "acme", "u", null,
                    null, null, "SUCCESS", Map.of()), json);

            final long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while (target.requests().isEmpty() && System.nanoTime() < until) {
                Thread.sleep(20);
            }
            assertThat(target.requests()).hasSize(1);
            final RebindingTarget.Seen seen = target.requests().get(0);
            assertThat(seen.method()).isEqualTo("POST");
            assertThat(seen.body()).isEqualTo(json);
            assertThat(seen.header("Content-Type")).isEqualTo("application/json");
            assertThat(seen.header("X-Helix-Event")).isEqualTo("audit");
            assertThat(seen.header("X-Helix-Signature")).isEqualTo("sha256=" + WebhookDispatcher.sign("s3cret", json));
            assertThat(target.lookups()).isEqualTo(1);
        }
    }
}
