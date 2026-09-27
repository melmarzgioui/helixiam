/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.fasterxml.jackson.databind.JsonNode;
import io.helixiam.e2e.AbstractE2eTest;
import io.helixiam.e2e.E2eAdminSession;
import io.helixiam.e2e.E2eSeed;
import io.helixiam.testsupport.CloudflareApiMock;
import io.helixiam.testsupport.TestSmtpServer;
import io.helixiam.testsupport.TestTls;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code POST /admin/realms/{r}/messaging/providers/{channel}/test} with an optional {@code driver}: it tests that
 * provider, even when it is disabled, and without one the realm's active provider.
 */
class EmailProviderTestEndpointE2eTest extends AbstractE2eTest {

    private static TestTls tls;
    private static CloudflareApiMock cloudflare;
    private static TestSmtpServer smtps;

    @BeforeAll
    static void startMailServers() {
        tls = TestTls.create("email-test-endpoint-e2e");
        cloudflare = CloudflareApiMock.https(tls).respond(r -> CloudflareApiMock.delivered(r.to()));
        HarnessEgressGuard.allow(cloudflare.port());
        smtps = TestSmtpServer.implicitTls(tls);
    }

    @AfterAll
    static void stopMailServers() {
        HarnessEgressGuard.revoke(cloudflare.port());
        cloudflare.close();
        smtps.close();
    }

    private static String providers(final String realm) {
        return "/admin/realms/" + realm + "/messaging/providers";
    }

    private static Map<String, Object> test(final String to, final String driver) {
        final Map<String, Object> body = new LinkedHashMap<>();
        body.put("to", to);
        if (driver != null) {
            body.put("driver", driver);
        }
        return body;
    }

    @Test
    void theTestSend_usesTheNamedProvider_evenWhenDisabled_andTheActiveOneOtherwise() {
        final String realm = E2eSeed.unique("acme-testsend");
        seed().realm(realm, "Acme");
        final E2eAdminSession admin = adminSession();
        final Map<String, Object> smtp = new LinkedHashMap<>(EmailDriversBrowserE2eTest.smtpsProvider(smtps, tls));
        smtp.put("enabled", false);
        assertThat(admin.put(providers(realm), smtp).status()).isEqualTo(200);
        assertThat(admin.put(providers(realm), EmailDriversBrowserE2eTest.cloudflareProvider(cloudflare, tls)).status())
                .isEqualTo(200);

        // Named, disabled: the SMTPS server gets it.
        final String viaSmtp = E2eSeed.unique("smtp") + "@example.com";
        final JsonNode smtpResult = admin.post(providers(realm) + "/EMAIL/test", test(viaSmtp, "smtp")).json();
        assertThat(smtpResult.path("sent").asBoolean()).isTrue();
        assertThat(smtpResult.path("result").asText()).isEqualTo("ACCEPTED");
        assertThat(smtpResult.path("driver").asText()).isEqualTo("SMTP");
        assertThat(smtps.await(r -> String.join(",", r.rcptTo()).contains(viaSmtp), Duration.ofSeconds(10))).isNotNull();
        assertThat(cloudflare.requests().stream().filter(r -> viaSmtp.equals(r.to()))).isEmpty();

        // No driver: the active (enabled) provider, Cloudflare.
        final String viaActive = E2eSeed.unique("active") + "@example.com";
        final JsonNode active = admin.post(providers(realm) + "/EMAIL/test", test(viaActive, null)).json();
        assertThat(active.path("sent").asBoolean()).isTrue();
        assertThat(active.path("driver").asText()).isEqualTo("CLOUDFLARE");
        assertThat(cloudflare.await(r -> viaActive.equals(r.to()), Duration.ofSeconds(5))).isNotNull();

        // A known driver the realm has not configured.
        final JsonNode missing = admin.post(providers(realm) + "/EMAIL/test", test("x@example.com", "HTTP")).json();
        assertThat(missing.path("sent").asBoolean()).isFalse();
        assertThat(missing.path("message").asText()).contains("HTTP");

        // A driver the channel does not know: 400 with a field error.
        final var unknown = admin.post(providers(realm) + "/EMAIL/test", test("x@example.com", "PIGEON"));
        assertThat(unknown.status()).isEqualTo(400);
        assertThat(unknown.json().path("fieldErrors").path("driver").asText()).contains("Unknown EMAIL driver");
    }
}
