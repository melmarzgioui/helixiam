/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.fasterxml.jackson.databind.JsonNode;
import io.helixiam.authorization.messaging.MessagingService;
import io.helixiam.authorization.messaging.email.DeliveryResult;
import io.helixiam.authorization.messaging.email.EmailDeliveryException;
import io.helixiam.authorization.messaging.email.JdbcBounceRecorder;
import io.helixiam.e2e.AbstractE2eTest;
import io.helixiam.e2e.E2eAdminSession;
import io.helixiam.e2e.E2eSeed;
import io.helixiam.testsupport.CloudflareApiMock;
import io.helixiam.testsupport.TestTls;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Bounced addresses on the real server: a permanent bounce reported by the provider marks the user's address
 * ({@code emailBounced}, {@code emailBouncedAt} in the admin user API) and is not retried; the mark clears when the
 * address changes or is verified again.
 */
class EmailBounceE2eTest extends AbstractE2eTest {

    private static TestTls tls;
    private static CloudflareApiMock cloudflare;

    @BeforeAll
    static void startMock() {
        tls = TestTls.create("email-bounce-e2e");
        cloudflare = CloudflareApiMock.https(tls).respond(r -> r.to() != null && r.to().startsWith("bounce")
                ? CloudflareApiMock.Response.of(200, "{\"success\":true,\"errors\":[],\"result\":{\"delivered\":[],"
                + "\"permanent_bounces\":[\"" + r.to() + "\"],\"queued\":[]}}")
                : CloudflareApiMock.delivered(r.to()));
        HarnessEgressGuard.allow(cloudflare.port());
    }

    @AfterAll
    static void stopMock() {
        HarnessEgressGuard.revoke(cloudflare.port());
        cloudflare.close();
    }

    private static String user(final String realm, final String userId) {
        return "/admin/realms/" + realm + "/users/" + userId;
    }

    private static Map<String, Object> update(final JsonNode current, final String email, final Boolean verified) {
        final Map<String, Object> body = new LinkedHashMap<>();
        body.put("username", current.path("username").asText());
        body.put("email", email);
        body.put("enabled", true);
        body.put("locked", false);
        if (verified != null) {
            body.put("emailVerified", verified);
        }
        return body;
    }

    @Test
    void aBounceFromTheProvider_marksTheUser_andClearsWhenTheAddressChangesOrIsVerifiedAgain() {
        final String realm = E2eSeed.unique("acme-bounce");
        seed().realm(realm, "Acme");
        final E2eAdminSession admin = adminSession();
        assertThat(admin.put("/admin/realms/" + realm + "/messaging/providers",
                EmailDriversBrowserE2eTest.cloudflareProvider(cloudflare, tls)).status()).isEqualTo(200);
        final String username = E2eSeed.unique("bounce");
        final E2eSeed.SeededUser seeded = seed().user(realm, username, "Bounce-Passw0rd!");
        final String address = username + "@e2e.helixiam.test";
        assertThat(admin.get(user(realm, seeded.userId())).json().path("emailBounced").asBoolean()).isFalse();

        // A real send through the realm's provider (the OTP email), which reports a permanent bounce.
        final long before = Instant.now().toEpochMilli();
        assertThatThrownBy(() -> context.getBean(MessagingService.class).sendEmail(realm, address, "otp-email",
                Map.of("code", "123456"), java.time.Duration.ofMinutes(5)))
                .isInstanceOfSatisfying(EmailDeliveryException.class, e -> assertThat(e.result().reason())
                        .isEqualTo(DeliveryResult.Reason.RECIPIENT_BOUNCED));

        JsonNode dto = admin.get(user(realm, seeded.userId())).json();
        assertThat(dto.path("emailBounced").asBoolean()).isTrue();
        assertThat(dto.path("emailBouncedAt").asLong()).isBetween(before, Instant.now().toEpochMilli());
        // Not retried: a bounce is permanent.
        assertThat(context.getBean(org.springframework.jdbc.core.JdbcTemplate.class).queryForObject(
                "SELECT count(*) FROM email_retry WHERE realm_id = ?", Long.class, realm)).isZero();
        assertThat(cloudflare.requests().stream().filter(r -> address.equals(r.to()))).hasSize(1);
        // The server's metrics: attempts, latency, the bounce, and the retry-queue gauge.
        final io.micrometer.core.instrument.MeterRegistry registry =
                context.getBean(io.micrometer.core.instrument.MeterRegistry.class);
        assertThat(registry.find("helix_email_send_total").tags("realm", realm, "driver", "CLOUDFLARE", "result",
                "PERMANENT_FAILURE").counter().count()).isEqualTo(1.0);
        assertThat(registry.find("helix_email_send_duration").tags("realm", realm, "driver", "CLOUDFLARE").timer()
                .count()).isEqualTo(1);
        assertThat(registry.find("helix_email_bounces_total").tags("realm", realm).counter().count()).isEqualTo(1.0);
        assertThat(registry.find("helix_email_retry_queued").gauge()).isNotNull();

        // A new address: the bounce was about the old one.
        final String newAddress = E2eSeed.unique("new") + "@example.org";
        dto = admin.put(user(realm, seeded.userId()), update(dto, newAddress, null)).json();
        assertThat(dto.path("emailBounced").asBoolean()).isFalse();
        assertThat(dto.path("emailBouncedAt").isNull() || dto.path("emailBouncedAt").isMissingNode()).isTrue();
        final JsonNode stored = admin.get(user(realm, seeded.userId())).json();
        assertThat(stored.path("emailBounced").asBoolean()).isFalse();

        // The new address bounces too; verifying it again clears the mark.
        context.getBean(JdbcBounceRecorder.class).markBounced(realm, newAddress, Instant.now());
        dto = admin.get(user(realm, seeded.userId())).json();
        assertThat(dto.path("emailBounced").asBoolean()).isTrue();
        assertThat(dto.path("emailVerified").asBoolean()).isFalse();
        dto = admin.put(user(realm, seeded.userId()), update(dto, newAddress, true)).json();
        assertThat(dto.path("emailVerified").asBoolean()).isTrue();
        assertThat(dto.path("emailBounced").asBoolean()).isFalse();
        assertThat(admin.get(user(realm, seeded.userId())).json().path("emailBounced").asBoolean()).isFalse();
    }

    @Test
    void aBounceInAnotherRealm_doesNotMarkThisRealmsUser() {
        final String realm = E2eSeed.unique("acme-iso");
        seed().realm(realm, "Acme");
        final String username = E2eSeed.unique("iso");
        final E2eSeed.SeededUser seeded = seed().user(realm, username, "Bounce-Passw0rd!");

        context.getBean(JdbcBounceRecorder.class).markBounced(E2eSeed.unique("other-realm"),
                username + "@e2e.helixiam.test", Instant.now());

        assertThat(adminSession().get(user(realm, seeded.userId())).json().path("emailBounced").asBoolean()).isFalse();
    }
}
