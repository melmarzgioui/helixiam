/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.driver;

import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.authorization.messaging.email.DeliveryResult;
import io.helixiam.authorization.messaging.email.DeliveryResult.Reason;
import io.helixiam.authorization.messaging.email.DeliveryResult.Status;
import io.helixiam.authorization.messaging.email.EmailAddress;
import io.helixiam.authorization.messaging.email.EmailMessage;
import io.helixiam.authorization.messaging.email.SmtpTlsMode;
import io.helixiam.common.startup.DeploymentProfile;
import io.helixiam.testsupport.TestSmtpServer;
import io.helixiam.testsupport.TestTls;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.ServerSocket;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The SMTP driver against a local SMTP server: implicit TLS against a TLS-only server, STARTTLS required / optional,
 * certificate validation, the deprecated {@code starttls} boolean, plain text only in dev, and the classification of
 * SMTP replies (5xx permanent, 4xx and connection / TLS errors transient).
 */
class SmtpEmailDriverTest {

    private static final String PASSWORD = "smtp-test-password-19";
    private static TestTls tls;

    @BeforeAll
    static void certs() {
        tls = TestTls.create("smtp");
    }

    private static SmtpEmailDriver driver() {
        return new SmtpEmailDriver(DeploymentProfile.production());
    }

    private static ResolvedProviderDto provider(final int port, final Map<String, String> extra) {
        final Map<String, String> config = new LinkedHashMap<>();
        config.put("host", "localhost");
        config.put("port", String.valueOf(port));
        config.put("username", "mailer");
        config.put("connectTimeoutMs", "3000");
        config.put("readTimeoutMs", "5000");
        config.putAll(extra);
        return new ResolvedProviderDto("EMAIL", "SMTP", "no-reply@example.com", "Example", config, PASSWORD);
    }

    private static EmailMessage message() {
        return new EmailMessage("7d0c2d4e-stable-id", null, List.of(EmailAddress.of("ada@example.org", "Ada")),
                EmailAddress.of("support@example.com"), "Reset your password",
                "<p><a href=\"https://idp.example.com/reset/abc\">Choose a new password</a></p>",
                "Choose a new password:\nhttps://idp.example.com/reset/abc", Map.of());
    }

    @Test
    void implicitTls_againstATlsOnlyServer_deliversTextAndHtml() throws Exception {
        try (TestSmtpServer server = TestSmtpServer.implicitTls(tls)) {
            final DeliveryResult result = driver().deliver(provider(server.port(),
                    Map.of("tlsMode", "IMPLICIT", "caBundle", tls.caPem(), "ehloName", "idp.example.com")), message());

            assertThat(result.status()).as(String.valueOf(result)).isEqualTo(Status.ACCEPTED);
            final TestSmtpServer.Received received = server.await(r -> true, Duration.ofSeconds(5));
            assertThat(received.tls()).isTrue();
            assertThat(received.authUser()).isEqualTo("mailer");
            assertThat(received.authPassword()).isEqualTo(PASSWORD);
            assertThat(received.ehlo()).isEqualTo("idp.example.com");
            assertThat(received.rcptTo()).containsExactly("<ada@example.org>");
            final MimeMessage mime = received.mime();
            assertThat(mime.getMessageID()).isEqualTo("<7d0c2d4e-stable-id@example.com>");
            assertThat(result.providerMessageId()).isEqualTo("<7d0c2d4e-stable-id@example.com>");
            assertThat(mime.getReplyTo()[0].toString()).isEqualTo("support@example.com");
            final MimeMultipart parts = (MimeMultipart) mime.getContent();
            assertThat(parts.getContentType()).contains("multipart/alternative");
            assertThat(parts.getBodyPart(0).getContentType()).contains("text/plain");
            assertThat((String) parts.getBodyPart(0).getContent()).contains("https://idp.example.com/reset/abc");
            assertThat(parts.getBodyPart(1).getContentType()).contains("text/html");
        }
    }

    @Test
    void implicitTls_defaultsToPort465() {
        assertThat(SmtpEmailDriver.Settings.of(Map.of("host", "smtp.example.com", "tlsMode", "IMPLICIT")).port())
                .isEqualTo(465);
        assertThat(SmtpEmailDriver.Settings.of(Map.of("host", "smtp.example.com")).port()).isEqualTo(587);
        assertThat(SmtpEmailDriver.Settings.of(Map.of("host", "smtp.example.com")).tlsMode())
                .isEqualTo(SmtpTlsMode.STARTTLS_REQUIRED);
    }

    @Test
    void theDeprecatedStarttlsBoolean_mapsToTlsMode_andTlsModeWins() {
        assertThat(SmtpTlsMode.resolve(null, "true")).isEqualTo(SmtpTlsMode.STARTTLS_REQUIRED);
        assertThat(SmtpTlsMode.resolve(null, "false")).isEqualTo(SmtpTlsMode.STARTTLS_OPTIONAL);
        assertThat(SmtpTlsMode.resolve("implicit", "true")).isEqualTo(SmtpTlsMode.IMPLICIT);
        assertThat(SmtpTlsMode.resolve(null, null)).isEqualTo(SmtpTlsMode.STARTTLS_REQUIRED);
        assertThatThrownBy(() -> SmtpTlsMode.resolve("TLS", null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void starttlsRequired_againstAServerWithoutStarttls_fails_andNothingIsSent() {
        try (TestSmtpServer server = TestSmtpServer.plain()) {
            final DeliveryResult result = driver().deliver(provider(server.port(),
                    Map.of("tlsMode", "STARTTLS_REQUIRED")), message());

            assertThat(result.status()).isEqualTo(Status.TRANSIENT_FAILURE);
            assertThat(result.diagnostic()).contains("STARTTLS");
            assertThat(server.received()).isEmpty();
            assertThat(server.commands()).noneMatch(c -> c.startsWith("AUTH") || c.startsWith("MAIL"));
        }
    }

    @Test
    void theLegacyStarttlsTrue_isNowRequired() {
        try (TestSmtpServer server = TestSmtpServer.plain()) {
            final DeliveryResult result = driver().deliver(provider(server.port(), Map.of("starttls", "true")),
                    message());

            assertThat(result.status()).isEqualTo(Status.TRANSIENT_FAILURE);
            assertThat(server.received()).isEmpty();
        }
    }

    @Test
    void starttlsRequired_upgradesTheConnection_withTheCaBundle() {
        try (TestSmtpServer server = TestSmtpServer.startTls(tls)) {
            final DeliveryResult result = driver().deliver(provider(server.port(),
                    Map.of("tlsMode", "STARTTLS_REQUIRED", "caBundle", tls.caPem())), message());

            assertThat(result.status()).as(String.valueOf(result)).isEqualTo(Status.ACCEPTED);
            assertThat(server.await(r -> true, Duration.ofSeconds(5)).tls()).isTrue();
        }
    }

    @Test
    void starttlsOptional_sendsInPlainTextWhenTheServerHasNoStarttls() {
        try (TestSmtpServer server = TestSmtpServer.plain()) {
            final DeliveryResult result = driver().deliver(provider(server.port(), Map.of("starttls", "false")),
                    message());

            assertThat(result.status()).as(String.valueOf(result)).isEqualTo(Status.ACCEPTED);
            assertThat(server.await(r -> true, Duration.ofSeconds(5)).tls()).isFalse();
        }
    }

    @Test
    void anUntrustedCertificate_failsValidation_implicit() {
        try (TestSmtpServer server = TestSmtpServer.implicitTls(tls)) {
            final DeliveryResult result = driver().deliver(provider(server.port(), Map.of("tlsMode", "IMPLICIT")),
                    message());

            assertThat(result.status()).isEqualTo(Status.TRANSIENT_FAILURE);
            assertThat(result.reason()).isEqualTo(Reason.NETWORK);
            assertThat(result.diagnostic()).contains("TLS");
            assertThat(server.received()).isEmpty();
        }
    }

    @Test
    void anUntrustedCertificate_failsValidation_starttls() {
        try (TestSmtpServer server = TestSmtpServer.startTls(tls)) {
            final DeliveryResult result = driver().deliver(provider(server.port(),
                    Map.of("tlsMode", "STARTTLS_REQUIRED", "caBundle", TestTls.create("other").caPem())), message());

            assertThat(result.status()).isEqualTo(Status.TRANSIENT_FAILURE);
            assertThat(result.reason()).isEqualTo(Reason.NETWORK);
            assertThat(server.received()).isEmpty();
        }
    }

    @Test
    void aHostNameThatIsNotInTheCertificate_failsValidation() {
        final TestTls otherHost = TestTls.createFor("smtp-other-host", "mail.example.com");
        try (TestSmtpServer server = TestSmtpServer.implicitTls(otherHost)) {
            final DeliveryResult result = driver().deliver(provider(server.port(),
                    Map.of("tlsMode", "IMPLICIT", "caBundle", otherHost.caPem())), message());

            assertThat(result.status()).isEqualTo(Status.TRANSIENT_FAILURE);
            assertThat(result.reason()).isEqualTo(Reason.NETWORK);
            assertThat(server.received()).isEmpty();
        }
    }

    @Test
    void a5xxOnTheRecipient_isAPermanentBounce() {
        try (TestSmtpServer server = TestSmtpServer.implicitTls(tls).replyToRcpt("550 5.1.1 No such user here")) {
            final DeliveryResult result = driver().deliver(provider(server.port(),
                    Map.of("tlsMode", "IMPLICIT", "caBundle", tls.caPem())), message());

            assertThat(result.status()).isEqualTo(Status.PERMANENT_FAILURE);
            assertThat(result.reason()).isEqualTo(Reason.RECIPIENT_BOUNCED);
            assertThat(result.bouncedRecipients()).containsExactly("ada@example.org");
            assertThat(result.diagnostic()).startsWith("SMTP 550").contains("No such user");
        }
    }

    @Test
    void a5xxOnData_isPermanent() {
        try (TestSmtpServer server = TestSmtpServer.implicitTls(tls).replyToData("554 5.7.1 Message rejected")) {
            final DeliveryResult result = driver().deliver(provider(server.port(),
                    Map.of("tlsMode", "IMPLICIT", "caBundle", tls.caPem())), message());

            assertThat(result.status()).isEqualTo(Status.PERMANENT_FAILURE);
            assertThat(result.diagnostic()).startsWith("SMTP 554");
        }
    }

    @Test
    void a4xx_isTransient() {
        try (TestSmtpServer server = TestSmtpServer.implicitTls(tls).replyToData("451 4.3.0 Try again later")) {
            final DeliveryResult result = driver().deliver(provider(server.port(),
                    Map.of("tlsMode", "IMPLICIT", "caBundle", tls.caPem())), message());

            assertThat(result.status()).isEqualTo(Status.TRANSIENT_FAILURE);
            assertThat(result.diagnostic()).startsWith("SMTP 451");
        }
        try (TestSmtpServer server = TestSmtpServer.implicitTls(tls).replyToRcpt("450 4.2.1 Mailbox busy")) {
            final DeliveryResult result = driver().deliver(provider(server.port(),
                    Map.of("tlsMode", "IMPLICIT", "caBundle", tls.caPem())), message());

            assertThat(result.status()).isEqualTo(Status.TRANSIENT_FAILURE);
            assertThat(result.bouncedRecipients()).isEmpty();
        }
    }

    @Test
    void refusedCredentials_arePermanent_andNeverEchoTheSecret() {
        try (TestSmtpServer server = TestSmtpServer.implicitTls(tls)
                .replyToAuth("535 5.7.8 Authentication credentials invalid")) {
            final DeliveryResult result = driver().deliver(provider(server.port(),
                    Map.of("tlsMode", "IMPLICIT", "caBundle", tls.caPem())), message());

            assertThat(result.status()).isEqualTo(Status.PERMANENT_FAILURE);
            assertThat(result.reason()).isEqualTo(Reason.AUTHENTICATION);
            assertThat(result.diagnostic()).contains("535").doesNotContain(PASSWORD);
        }
    }

    @Test
    void aConnectionFailure_isTransient() throws Exception {
        final int closedPort;
        try (ServerSocket s = new ServerSocket(0)) {
            closedPort = s.getLocalPort();
        }
        final DeliveryResult result = driver().deliver(provider(closedPort,
                Map.of("tlsMode", "IMPLICIT", "caBundle", tls.caPem())), message());

        assertThat(result.status()).isEqualTo(Status.TRANSIENT_FAILURE);
        assertThat(result.reason()).isEqualTo(Reason.NETWORK);
    }

    @Test
    void tlsModeNone_isRefusedOutsideDev_andWorksInDev() {
        try (TestSmtpServer server = TestSmtpServer.plain()) {
            final DeliveryResult prod = driver().deliver(provider(server.port(), Map.of("tlsMode", "NONE")), message());
            assertThat(prod.status()).isEqualTo(Status.PERMANENT_FAILURE);
            assertThat(prod.reason()).isEqualTo(Reason.CONFIGURATION);
            assertThat(server.commands()).isEmpty();

            final DeliveryResult dev = new SmtpEmailDriver(DeploymentProfile.development())
                    .deliver(provider(server.port(), Map.of("tlsMode", "NONE")), message());
            assertThat(dev.status()).as(String.valueOf(dev)).isEqualTo(Status.ACCEPTED);
        }
    }

    @Test
    void invalidSettings_areConfigurationFailures() {
        assertThat(driver().deliver(new ResolvedProviderDto("EMAIL", "SMTP", "no-reply@example.com", null,
                Map.of(), null), message()).reason()).isEqualTo(Reason.CONFIGURATION);
        assertThat(driver().deliver(provider(70000, Map.of()), message()).reason()).isEqualTo(Reason.CONFIGURATION);
        assertThat(driver().deliver(provider(587, Map.of("tlsMode", "SSL")), message()).reason())
                .isEqualTo(Reason.CONFIGURATION);
        assertThat(driver().deliver(provider(587, Map.of("caBundle", "not a certificate")), message()).reason())
                .isEqualTo(Reason.CONFIGURATION);
    }
}
