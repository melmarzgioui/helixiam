/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.driver;

import io.helixiam.authorization.messaging.email.EmailAddress;
import io.helixiam.authorization.messaging.email.EmailMessage;
import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.common.startup.DeploymentProfile;
import io.helixiam.testsupport.RebindingTarget;
import io.helixiam.testsupport.TestTls;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * M6: the realm-configured notification HTTP endpoints (HTTP email / SMS drivers, push, and the Cloudflare email API)
 * are called on the address the guard validated, never on a second DNS answer.
 */
class NotificationTransportRebindingTest {

    @Test
    void theHttpTransportPostsToTheValidatedAddressOnly() {
        try (RebindingTarget target = RebindingTarget.http("sms.rebind.test")) {
            target.respond(s -> new RebindingTarget.Answer(202, "application/json", "{\"id\":\"m-1\"}"));
            final HttpTransport transport = new HttpTransport.Default(target.guard());

            final HttpTransport.Response r = transport.postForResponse(target.url("http", "/send"),
                    Map.of("Content-Type", "application/json", "Authorization", "Bearer k"), "{\"to\":\"+31600000000\"}");

            assertThat(r.status()).isEqualTo(202);
            assertThat(r.body()).isEqualTo("{\"id\":\"m-1\"}");
            assertThat(target.requests()).hasSize(1);
            assertThat(target.requests().get(0).body()).isEqualTo("{\"to\":\"+31600000000\"}");
            assertThat(target.requests().get(0).header("Authorization")).isEqualTo("Bearer k");
            assertThat(target.lookups()).isEqualTo(1);
        }
    }

    @Test
    void theCloudflareApiIsCalledOnTheValidatedAddressOnly() {
        final TestTls tls = TestTls.createFor("cloudflare-rebind", "api.rebind.test");
        try (RebindingTarget target = RebindingTarget.https("api.rebind.test", tls)) {
            target.respond(s -> new RebindingTarget.Answer(200, "application/json",
                    "{\"success\":true,\"errors\":[],\"messages\":[],\"result\":{\"delivered\":[\"ada@example.com\"],"
                            + "\"permanent_bounces\":[],\"queued\":[]}}"));
            final Map<String, String> config = new LinkedHashMap<>();
            config.put("accountId", "0123456789abcdef0123456789abcdef");
            config.put("baseUrl", target.url("https", "/client/v4"));
            config.put("caBundle", tls.caPem());
            final CloudflareEmailDriver driver = new CloudflareEmailDriver(target.guard(),
                    DeploymentProfile.production());

            driver.deliver(new ResolvedProviderDto("EMAIL", "CLOUDFLARE", "no-reply@example.com", "Example", config,
                    "cf-token"), new EmailMessage(EmailMessage.newMessageId(), null,
                    List.of(EmailAddress.of("ada@example.com", "Ada")), null, "Hi", null, "Hello", Map.of()));

            assertThat(target.requests()).hasSize(1);
            assertThat(target.requests().get(0).method()).isEqualTo("POST");
            assertThat(target.requests().get(0).header("Authorization")).isEqualTo("Bearer cf-token");
            assertThat(target.lookups()).isEqualTo(1);
        }
    }

    @Test
    void aCloudflareTokenThatCannotBeAHeaderIsAConfigurationFailure() {
        final Map<String, String> config = new LinkedHashMap<>();
        config.put("accountId", "0123456789abcdef0123456789abcdef");
        final CloudflareEmailDriver driver = new CloudflareEmailDriver(io.helixiam.common.net.OutboundUrlGuard.permissive(),
                DeploymentProfile.production());
        final io.helixiam.authorization.messaging.email.DeliveryResult result = driver.deliver(new ResolvedProviderDto(
                "EMAIL", "CLOUDFLARE", "no-reply@example.com", "Example", config, "t\u00f6ken"),
                new EmailMessage(EmailMessage.newMessageId(), null, List.of(EmailAddress.of("ada@example.com", "Ada")),
                        null, "Hi", null, "Hello", Map.of()));
        assertThat(result.status()).isEqualTo(io.helixiam.authorization.messaging.email.DeliveryResult.Status
                .PERMANENT_FAILURE);
        assertThat(result.reason()).isEqualTo(io.helixiam.authorization.messaging.email.DeliveryResult.Reason
                .CONFIGURATION);
        assertThat(result.diagnostic()).doesNotContain("t\u00f6ken");
    }
}
