/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.fasterxml.jackson.databind.JsonNode;
import io.helixiam.e2e.AbstractE2eTest;
import io.helixiam.e2e.E2eAdminSession;
import io.helixiam.e2e.E2eHttp;
import io.helixiam.e2e.E2eSeed;
import io.helixiam.testsupport.CloudflareApiMock;
import io.helixiam.testsupport.LogCapture;
import io.helixiam.testsupport.TestSmtpServer;
import io.helixiam.testsupport.TestTls;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.ServerSocket;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The email-provider admin API on the real server: validation on save (400 {@code {message, fieldErrors}}), the
 * test endpoint's classified result, write-only secrets (never in the API, the realm export or the logs), https-only
 * base URLs outside dev, and the egress guard on the Cloudflare driver.
 */
class EmailProviderAdminE2eTest extends AbstractE2eTest {

    private static TestTls tls;
    private static CloudflareApiMock cloudflare;
    private static TestSmtpServer smtps;

    @BeforeAll
    static void startMailServers() {
        tls = TestTls.create("email-admin-e2e");
        cloudflare = CloudflareApiMock.https(tls).respond(r -> r.to() != null && r.to().startsWith("denied")
                ? CloudflareApiMock.Response.of(401, "{\"success\":false,\"errors\":[{\"code\":10000,"
                + "\"message\":\"Authentication error\"}]}")
                : r.to() != null && r.to().startsWith("bounce")
                ? CloudflareApiMock.Response.of(200, "{\"success\":true,\"errors\":[],\"result\":{\"delivered\":[],"
                + "\"permanent_bounces\":[\"" + r.to() + "\"],\"queued\":[]}}")
                : CloudflareApiMock.delivered(r.to()));
        HarnessEgressGuard.allow(cloudflare.port());
        smtps = TestSmtpServer.implicitTls(tls);
    }

    @AfterAll
    static void stopMailServers() {
        HarnessEgressGuard.revoke(cloudflare.port());
        cloudflare.close();
        smtps.close();
    }

    private String realm() {
        final String realm = E2eSeed.unique("acme-admin");
        seed().realm(realm, "Acme");
        return realm;
    }

    private static String providers(final String realm) {
        return "/admin/realms/" + realm + "/messaging/providers";
    }

    @Test
    void theTestEndpoint_sendsARealEmail_andReturnsTheClassifiedResult() {
        final String realm = realm();
        final E2eAdminSession admin = adminSession();
        assertThat(admin.put(providers(realm), EmailDriversBrowserE2eTest.cloudflareProvider(cloudflare, tls)).status())
                .isEqualTo(200);

        final String inbox = E2eSeed.unique("ok") + "@example.com";
        final JsonNode ok = admin.post(providers(realm) + "/EMAIL/test", Map.of("to", inbox)).json();
        assertThat(ok.path("sent").asBoolean()).isTrue();
        assertThat(ok.path("result").asText()).isEqualTo("ACCEPTED");
        assertThat(ok.path("diagnostic").asText()).contains("HTTP 200");
        final CloudflareApiMock.Request request = cloudflare.await(r -> inbox.equals(r.to()), java.time.Duration.ofSeconds(5));
        assertThat(request.json().path("text").asText()).contains("123456");

        final JsonNode bounced = admin.post(providers(realm) + "/EMAIL/test",
                Map.of("to", E2eSeed.unique("bounce") + "@example.com")).json();
        assertThat(bounced.path("sent").asBoolean()).isFalse();
        assertThat(bounced.path("result").asText()).isEqualTo("PERMANENT_FAILURE");
        assertThat(bounced.path("reason").asText()).isEqualTo("RECIPIENT_BOUNCED");

        final MeterRegistry registry = context.getBean(MeterRegistry.class);
        final double before = authFailures(registry, realm);
        final JsonNode denied = admin.post(providers(realm) + "/EMAIL/test",
                Map.of("to", E2eSeed.unique("denied") + "@example.com")).json();
        assertThat(denied.path("sent").asBoolean()).isFalse();
        assertThat(denied.path("result").asText()).isEqualTo("TRANSIENT_FAILURE");
        assertThat(denied.path("reason").asText()).isEqualTo("AUTHENTICATION");
        assertThat(denied.path("diagnostic").asText()).contains("HTTP 401").contains("10000 Authentication error")
                .doesNotContain(EmailDriversBrowserE2eTest.CF_TOKEN);
        assertThat(authFailures(registry, realm)).isEqualTo(before + 1);
        assertThat(registry.find("helix_email_send_total").tags("realm", realm, "driver", "CLOUDFLARE",
                "result", "TRANSIENT_FAILURE").counter().count()).isEqualTo(1.0);
        assertThat(registry.find("helix_email_send_total").tags("realm", realm, "driver", "CLOUDFLARE",
                "result", "ACCEPTED").counter().count()).isEqualTo(1.0);
    }

    private static double authFailures(final MeterRegistry registry, final String realm) {
        final Counter c = registry.find("helix_email_provider_auth_failures_total").tags("realm", realm).counter();
        return c == null ? 0 : c.count();
    }

    @Test
    void theTestEndpoint_classifiesSmtpOverImplicitTls() {
        final String realm = realm();
        final E2eAdminSession admin = adminSession();
        assertThat(admin.put(providers(realm), EmailDriversBrowserE2eTest.smtpsProvider(smtps, tls)).status())
                .isEqualTo(200);

        final JsonNode ok = admin.post(providers(realm) + "/EMAIL/test",
                Map.of("to", E2eSeed.unique("smtp") + "@example.com")).json();
        assertThat(ok.path("result").asText()).as(ok.toString()).isEqualTo("ACCEPTED");
        assertThat(ok.path("providerMessageId").asText()).startsWith("<").endsWith("@acme.example.com>");
    }

    @Test
    void secretsAreWriteOnly_inTheApi_theExport_andTheLogs() {
        final String realm = realm();
        final E2eAdminSession admin = adminSession();
        try (LogCapture logs = LogCapture.all(); LogCapture audit = LogCapture.named("helix.audit")) {
            assertThat(admin.put(providers(realm), EmailDriversBrowserE2eTest.cloudflareProvider(cloudflare, tls))
                    .status()).isEqualTo(200);
            // A credential typed into config is moved to the encrypted, write-only secret.
            final Map<String, Object> smtp = EmailDriversBrowserE2eTest.smtpsProvider(smtps, tls);
            final Map<String, String> config = new LinkedHashMap<>(castMap(smtp.get("config")));
            config.put("password", EmailDriversBrowserE2eTest.SMTP_PASSWORD);
            smtp.put("config", config);
            smtp.remove("secret");
            smtp.put("enabled", false);
            final E2eHttp.Response savedSmtp = admin.put(providers(realm), smtp);
            assertThat(savedSmtp.status()).isEqualTo(200);
            assertThat(savedSmtp.json().path("secretSet").asBoolean()).isTrue();

            admin.post(providers(realm) + "/EMAIL/test", Map.of("to", E2eSeed.unique("denied") + "@example.com"));
            admin.post(providers(realm) + "/EMAIL/test", Map.of("to", E2eSeed.unique("ok") + "@example.com"));

            final E2eHttp.Response list = admin.get(providers(realm));
            assertThat(list.status()).isEqualTo(200);
            assertThat(list.body()).contains("\"secretSet\":true").doesNotContain(EmailDriversBrowserE2eTest.CF_TOKEN)
                    .doesNotContain(EmailDriversBrowserE2eTest.SMTP_PASSWORD);

            final E2eHttp.Response export = admin.get("/admin/realms/" + realm + "/export");
            assertThat(export.status()).isEqualTo(200);
            assertThat(export.body()).contains("CLOUDFLARE").contains("${")
                    .doesNotContain(EmailDriversBrowserE2eTest.CF_TOKEN)
                    .doesNotContain(EmailDriversBrowserE2eTest.SMTP_PASSWORD);

            assertThat(logs.text()).as("server logs").contains("ACTION NEEDED")
                    .doesNotContain(EmailDriversBrowserE2eTest.CF_TOKEN)
                    .doesNotContain(EmailDriversBrowserE2eTest.SMTP_PASSWORD);
            assertThat(audit.text()).as("audit log").contains("EMAIL_PROVIDER_AUTH_FAILED")
                    .doesNotContain(EmailDriversBrowserE2eTest.CF_TOKEN);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> castMap(final Object o) {
        return (Map<String, String>) o;
    }

    @Test
    void validation_rejectsUnknownDrivers_missingFields_andUnsafeSettings() {
        final String realm = realm();
        final E2eAdminSession admin = adminSession();

        final E2eHttp.Response unknown = admin.put(providers(realm), Map.of("channel", "EMAIL", "driver", "PIGEON",
                "enabled", true, "fromAddress", "no-reply@example.com"));
        assertThat(unknown.status()).isEqualTo(400);
        assertThat(unknown.json().path("fieldErrors").has("driver")).isTrue();
        assertThat(unknown.json().path("message").asText()).contains("CLOUDFLARE");

        final E2eHttp.Response missing = admin.put(providers(realm), Map.of("channel", "EMAIL", "driver", "CLOUDFLARE",
                "enabled", true, "config", Map.of()));
        assertThat(missing.status()).isEqualTo(400);
        assertThat(missing.json().path("fieldErrors").has("config.accountId")).isTrue();
        assertThat(missing.json().path("fieldErrors").has("secret")).isTrue();
        assertThat(missing.json().path("fieldErrors").has("fromAddress")).isTrue();

        final Map<String, Object> http = EmailDriversBrowserE2eTest.cloudflareProvider(cloudflare, tls);
        http.put("config", Map.of("accountId", "acme01", "baseUrl", "http://api.example.com/client/v4"));
        final E2eHttp.Response httpBase = admin.put(providers(realm), http);
        assertThat(httpBase.status()).as("https only outside the dev profile").isEqualTo(400);
        assertThat(httpBase.json().path("fieldErrors").path("config.baseUrl").asText()).contains("https");

        final Map<String, Object> none = EmailDriversBrowserE2eTest.smtpsProvider(smtps, tls);
        none.put("config", Map.of("host", "localhost", "tlsMode", "NONE"));
        final E2eHttp.Response plain = admin.put(providers(realm), none);
        assertThat(plain.status()).isEqualTo(400);
        assertThat(plain.json().path("fieldErrors").has("config.tlsMode")).isTrue();

        final Map<String, Object> port = EmailDriversBrowserE2eTest.smtpsProvider(smtps, tls);
        port.put("config", Map.of("host", "localhost", "port", "0"));
        assertThat(admin.put(providers(realm), port).json().path("fieldErrors").has("config.port")).isTrue();

        assertThat(admin.get(providers(realm)).json().size()).as("nothing was saved").isZero();
    }

    @Test
    void theCloudflareDriver_passesTheEgressGuard() throws Exception {
        final String realm = realm();
        final E2eAdminSession admin = adminSession();
        final int unregistered;
        try (ServerSocket s = new ServerSocket(0)) {
            unregistered = s.getLocalPort();
        }
        final Map<String, Object> provider = EmailDriversBrowserE2eTest.cloudflareProvider(cloudflare, tls);
        provider.put("config", Map.of("accountId", "acme01", "baseUrl", "https://127.0.0.1:" + unregistered + "/client/v4",
                "caBundle", tls.caPem()));
        assertThat(admin.put(providers(realm), provider).status()).isEqualTo(200);

        final JsonNode result = admin.post(providers(realm) + "/EMAIL/test",
                Map.of("to", E2eSeed.unique("guard") + "@example.com")).json();

        assertThat(result.path("result").asText()).isEqualTo("PERMANENT_FAILURE");
        assertThat(result.path("reason").asText()).isEqualTo("CONFIGURATION");
        assertThat(result.path("diagnostic").asText()).contains("egress");
    }
}
