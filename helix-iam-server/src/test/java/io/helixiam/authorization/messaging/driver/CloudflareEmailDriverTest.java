/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.driver;

import com.fasterxml.jackson.databind.JsonNode;
import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.authorization.messaging.email.DeliveryResult;
import io.helixiam.authorization.messaging.email.DeliveryResult.Reason;
import io.helixiam.authorization.messaging.email.DeliveryResult.Status;
import io.helixiam.authorization.messaging.email.EmailAddress;
import io.helixiam.authorization.messaging.email.EmailMessage;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.startup.DeploymentProfile;
import io.helixiam.testsupport.CloudflareApiMock;
import io.helixiam.testsupport.LogCapture;
import io.helixiam.testsupport.TestTls;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.net.ServerSocket;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The Cloudflare Email Service driver against a local HTTPS mock: the exact request (URL, bearer token, the
 * {@code address} field, names, reply-to, html and text), every row of the classification table, the 1 MiB response
 * cap, the https-only base URL outside dev, the egress guard, certificate validation, and the token never showing up
 * in a diagnostic or a log.
 */
class CloudflareEmailDriverTest {

    private static final String TOKEN = "cf-test-token-7f3a9c";
    private static final String TO = "ada@example.org";
    private static TestTls tls;
    private static CloudflareApiMock mock;

    @BeforeAll
    static void start() {
        tls = TestTls.create("cloudflare");
        mock = CloudflareApiMock.https(tls);
    }

    @AfterAll
    static void stop() {
        mock.close();
    }

    @BeforeEach
    void reset() {
        mock.respond(r -> CloudflareApiMock.delivered(r.to()));
    }

    private static CloudflareEmailDriver driver() {
        return new CloudflareEmailDriver(OutboundUrlGuard.permissive(), DeploymentProfile.production());
    }

    private static ResolvedProviderDto provider(final String baseUrl, final String caPem, final String token) {
        final Map<String, String> config = new LinkedHashMap<>();
        config.put("accountId", "0123456789abcdef0123456789abcdef");
        config.put("baseUrl", baseUrl);
        if (caPem != null) {
            config.put("caBundle", caPem);
        }
        config.put("readTimeoutMs", "2000");
        return new ResolvedProviderDto("EMAIL", "CLOUDFLARE", "no-reply@example.com", "Example", config, token);
    }

    private static ResolvedProviderDto provider() {
        return provider(mock.baseUrl(), tls.caPem(), TOKEN);
    }

    private static EmailMessage message() {
        return new EmailMessage(EmailMessage.newMessageId(), null, List.of(EmailAddress.of(TO, "Ada Lovelace")),
                EmailAddress.of("support@example.com"), "Verify your email",
                "<p>Hi, <a href=\"https://idp.example.com/verify?t=abc\">verify</a></p>",
                "Hi, verify: https://idp.example.com/verify?t=abc", Map.of());
    }

    @Test
    void sendsTheExactRequestShape() {
        final DeliveryResult result = driver().deliver(provider(), message());

        assertThat(result.status()).isEqualTo(Status.ACCEPTED);
        final CloudflareApiMock.Request request = mock.requests().get(mock.requests().size() - 1);
        assertThat(request.method()).isEqualTo("POST");
        assertThat(request.path()).isEqualTo("/client/v4/accounts/0123456789abcdef0123456789abcdef/email/sending/send");
        assertThat(request.authorization()).isEqualTo("Bearer " + TOKEN);
        assertThat(request.contentType()).startsWith("application/json");
        final JsonNode body = request.json();
        assertThat(body.path("from").path("address").asText()).isEqualTo("no-reply@example.com");
        assertThat(body.path("from").path("name").asText()).isEqualTo("Example");
        assertThat(body.path("to").isArray()).isTrue();
        assertThat(body.path("to").path(0).path("address").asText()).isEqualTo(TO);
        assertThat(body.path("to").path(0).path("name").asText()).isEqualTo("Ada Lovelace");
        assertThat(body.path("reply_to").path("address").asText()).isEqualTo("support@example.com");
        assertThat(body.path("reply_to").has("name")).isFalse();
        assertThat(body.path("subject").asText()).isEqualTo("Verify your email");
        assertThat(body.path("html").asText()).contains("<a href=\"https://idp.example.com/verify?t=abc\">");
        assertThat(body.path("text").asText()).contains("https://idp.example.com/verify?t=abc");
        // The API rejects "email"; the field is "address" everywhere.
        assertThat(request.body()).doesNotContain("\"email\"");
    }

    @Test
    void anHtmlEmailWithoutATextPart_getsOneWithTheLink() {
        final EmailMessage html = EmailMessage.of(null, TO, "Reset",
                "<p><a href=\"https://idp.example.com/reset/abc\">Reset</a></p>", true, null);

        driver().deliver(provider(), html);

        final JsonNode body = mock.requests().get(mock.requests().size() - 1).json();
        assertThat(body.path("text").asText()).contains("https://idp.example.com/reset/abc").doesNotContain("<");
        assertThat(body.path("to").path(0).has("name")).isFalse();
        assertThat(body.has("reply_to")).isFalse();
    }

    @Test
    void aPlainEmailSendsTextOnly() {
        driver().deliver(provider(), EmailMessage.of(null, TO, "Code", "Your code is 123456", false, null));

        final JsonNode body = mock.requests().get(mock.requests().size() - 1).json();
        assertThat(body.has("html")).isFalse();
        assertThat(body.path("text").asText()).isEqualTo("Your code is 123456");
    }

    @ParameterizedTest(name = "{0} {1} -> {2} {3}")
    @CsvSource(delimiter = '|', value = {
            "200|delivered|ACCEPTED|NONE",
            "200|queued|QUEUED|NONE",
            "200|permanent_bounces|PERMANENT_FAILURE|RECIPIENT_BOUNCED",
            "400|error|PERMANENT_FAILURE|MESSAGE_REJECTED",
            "413|error|PERMANENT_FAILURE|MESSAGE_REJECTED",
            "401|error|TRANSIENT_FAILURE|AUTHENTICATION",
            "403|error|TRANSIENT_FAILURE|AUTHENTICATION",
            "429|error|TRANSIENT_FAILURE|RATE_LIMITED",
            "500|error|TRANSIENT_FAILURE|PROVIDER_ERROR",
            "502|error|TRANSIENT_FAILURE|PROVIDER_ERROR",
            "503|error|TRANSIENT_FAILURE|PROVIDER_ERROR",
    })
    void classifiesEveryRowOfTheTable(final int status, final String list, final Status expected, final Reason reason) {
        mock.respond(r -> CloudflareApiMock.Response.of(status, "error".equals(list)
                ? "{\"success\":false,\"errors\":[{\"code\":10001,\"message\":\"Something about the request\"}],"
                + "\"result\":null}"
                : "{\"success\":true,\"errors\":[],\"result\":{\"delivered\":[],\"permanent_bounces\":[],\"queued\":[],"
                + "\"" + list + "\":[\"" + r.to() + "\"]}}"));

        final DeliveryResult result = driver().deliver(provider(), message());

        assertThat(result.status()).isEqualTo(expected);
        assertThat(result.reason()).isEqualTo(reason);
        assertThat(result.diagnostic()).startsWith("HTTP " + status);
        if ("error".equals(list)) {
            assertThat(result.diagnostic()).contains("10001 Something about the request");
        }
        if (reason == Reason.RECIPIENT_BOUNCED) {
            assertThat(result.bouncedRecipients()).containsExactly(TO);
        }
    }

    @Test
    void aNetworkError_isTransient() throws Exception {
        final int closedPort;
        try (ServerSocket s = new ServerSocket(0)) {
            closedPort = s.getLocalPort();
        }
        final DeliveryResult result = driver().deliver(provider("https://127.0.0.1:" + closedPort + "/client/v4",
                tls.caPem(), TOKEN), message());

        assertThat(result.status()).isEqualTo(Status.TRANSIENT_FAILURE);
        assertThat(result.reason()).isEqualTo(Reason.NETWORK);
    }

    @Test
    void aTimeout_isTransient() {
        mock.respond(r -> new CloudflareApiMock.Response(200, "{\"success\":true}", 4_000));

        final DeliveryResult result = driver().deliver(provider(), message());

        assertThat(result.status()).isEqualTo(Status.TRANSIENT_FAILURE);
        assertThat(result.reason()).isEqualTo(Reason.NETWORK);
        assertThat(result.diagnostic()).contains("timed out");
    }

    @Test
    void anUntrustedCertificate_failsValidation_andIsTransient() {
        final DeliveryResult result = driver().deliver(provider(mock.baseUrl(), null, TOKEN), message());

        assertThat(result.status()).isEqualTo(Status.TRANSIENT_FAILURE);
        assertThat(result.reason()).isEqualTo(Reason.NETWORK);
        assertThat(result.diagnostic()).containsIgnoringCase("TLS");
    }

    @Test
    void readsAtMostOneMebibyteOfTheResponse() {
        final String huge = "{\"success\":false,\"errors\":[{\"code\":1,\"message\":\"" + "x".repeat(1_100_000) + "\"}]}";
        mock.respond(503, huge);

        final DeliveryResult result = driver().deliver(provider(), message());

        assertThat(result.status()).isEqualTo(Status.TRANSIENT_FAILURE);
        assertThat(result.diagnostic()).contains("over 1 MiB ignored").doesNotContain("xxxx");
        assertThat(result.diagnostic().length()).isLessThan(400);
    }

    @Test
    void theTokenIsNeverEchoed_notInTheDiagnostic_norInTheLogs() {
        mock.respond(401, "{\"success\":false,\"errors\":[{\"code\":10000,\"message\":\"Invalid token " + TOKEN
                + "\"}]}");
        try (LogCapture logs = LogCapture.of(CloudflareEmailDriver.class)) {
            final DeliveryResult result = driver().deliver(provider(), message());

            assertThat(result.reason()).isEqualTo(Reason.AUTHENTICATION);
            assertThat(result.diagnostic()).contains("10000").doesNotContain(TOKEN).contains("***");
            assertThat(logs.text()).doesNotContain(TOKEN);
        }
    }

    @Test
    void anHttpBaseUrl_isRefusedOutsideDev_andAllowedInDev() {
        try (CloudflareApiMock plain = CloudflareApiMock.http()) {
            final DeliveryResult prod = driver().deliver(provider(plain.baseUrl(), null, TOKEN), message());
            assertThat(prod.status()).isEqualTo(Status.PERMANENT_FAILURE);
            assertThat(prod.reason()).isEqualTo(Reason.CONFIGURATION);
            assertThat(prod.diagnostic()).contains("https");
            assertThat(plain.requests()).isEmpty();

            final DeliveryResult dev = new CloudflareEmailDriver(OutboundUrlGuard.permissive(),
                    DeploymentProfile.development()).deliver(provider(plain.baseUrl(), null, TOKEN), message());
            assertThat(dev.status()).isEqualTo(Status.ACCEPTED);
            assertThat(plain.requests()).hasSize(1);
        }
    }

    @Test
    void theEgressGuardApplies() {
        final int before = mock.requests().size();

        final DeliveryResult result = new CloudflareEmailDriver(OutboundUrlGuard.blocking(),
                DeploymentProfile.production()).deliver(provider(), message());

        assertThat(result.status()).isEqualTo(Status.PERMANENT_FAILURE);
        assertThat(result.reason()).isEqualTo(Reason.CONFIGURATION);
        assertThat(result.diagnostic()).contains("egress");
        assertThat(mock.requests()).hasSize(before);
    }

    @Test
    void missingSettings_areConfigurationFailures() {
        final DeliveryResult noToken = driver().deliver(provider(mock.baseUrl(), tls.caPem(), " "), message());
        assertThat(noToken.reason()).isEqualTo(Reason.CONFIGURATION);

        final DeliveryResult noAccount = driver().deliver(new ResolvedProviderDto("EMAIL", "CLOUDFLARE",
                "no-reply@example.com", null, Map.of("baseUrl", mock.baseUrl()), TOKEN), message());
        assertThat(noAccount.reason()).isEqualTo(Reason.CONFIGURATION);
        assertThat(noAccount.diagnostic()).contains("accountId");
    }

    @Test
    void theDefaultBaseUrl_isTheCloudflareApi() {
        final CloudflareEmailDriver.Settings settings = CloudflareEmailDriver.Settings.of(Map.of("accountId", "abc"),
                false);
        assertThat(settings.sendUrl()).isEqualTo("https://api.cloudflare.com/client/v4/accounts/abc/email/sending/send");
    }
}
