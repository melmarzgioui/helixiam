/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.driver;

import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM notifications (N6f): email templates can be HTML. When a template is flagged {@code html}, the
 * SMTP driver sends a {@code text/html} body (not {@code text/plain}) and the HTTP email driver marks the
 * payload {@code "html":true}, so rich formatted emails render in the recipient's client.
 */
class EmailDriverHtmlTest {

    private static ResolvedProviderDto smtpProvider() {
        return new ResolvedProviderDto("EMAIL", "SMTP", "no-reply@helix.test", "Helix",
                Map.of("host", "smtp.helix.test"), "pw");
    }

    @Test
    void smtpDriver_sendsTextHtmlContentType_whenHtml() throws Exception {
        final AtomicReference<MimeMessage> captured = new AtomicReference<>();
        final SmtpEmailDriver driver = new SmtpEmailDriver((session, message, username, password) -> captured.set(message));

        driver.send(smtpProvider(), "ada@helix.test", "Hi", "<h1>Hello</h1>", true);

        // Item 3: an HTML email is multipart/alternative, with a plain-text part derived from the HTML.
        assertThat(captured.get().getContentType()).contains("multipart/alternative");
        final MimeMultipart parts = (MimeMultipart) captured.get().getContent();
        assertThat(parts.getCount()).isEqualTo(2);
        assertThat(parts.getBodyPart(0).getContentType()).contains("text/plain");
        assertThat((String) parts.getBodyPart(0).getContent()).isEqualTo("Hello");
        assertThat(parts.getBodyPart(1).getContentType()).contains("text/html");
        assertThat((String) parts.getBodyPart(1).getContent()).isEqualTo("<h1>Hello</h1>");
    }

    @Test
    void smtpDriver_sendsTheGivenTextPart_withTheLink() throws Exception {
        final AtomicReference<MimeMessage> captured = new AtomicReference<>();
        final SmtpEmailDriver driver = new SmtpEmailDriver((session, message, username, password) -> captured.set(message));

        driver.send(smtpProvider(), "ada@helix.test", "Verify", "<p><a href=\"https://idp/v?t=1\" data-button>Verify</a></p>",
                true, "Verify: https://idp/v?t=1\n\nCode: 0b7c");

        captured.get().writeTo(java.io.OutputStream.nullOutputStream()); // the message serialises
        final MimeMultipart parts = (MimeMultipart) captured.get().getContent();
        assertThat((String) parts.getBodyPart(0).getContent()).isEqualTo("Verify: https://idp/v?t=1\n\nCode: 0b7c");
        assertThat(parts.getBodyPart(0).getContentType()).contains("charset=UTF-8");
    }

    @Test
    void smtpDriver_sendsTextPlainContentType_whenNotHtml() throws Exception {
        final AtomicReference<MimeMessage> captured = new AtomicReference<>();
        final SmtpEmailDriver driver = new SmtpEmailDriver((session, message, username, password) -> captured.set(message));

        driver.send(smtpProvider(), "ada@helix.test", "Hi", "plain body", false);

        assertThat(captured.get().getContentType()).contains("text/plain");
    }

    @Test
    void httpDriver_marksPayloadHtml_whenHtml() {
        final AtomicReference<String> body = new AtomicReference<>();
        final HttpTransport transport = (url, headers, payload) -> {
            body.set(payload);
            return 202;
        };
        final HttpEmailDriver driver = new HttpEmailDriver(transport);
        final Map<String, String> config = new LinkedHashMap<>();
        config.put("url", "https://email.api/send");

        driver.send(new ResolvedProviderDto("EMAIL", "HTTP", "no-reply@helix.test", "Helix", config, "key"),
                "ada@helix.test", "Hi", "<p>Hello</p>", true);

        assertThat(body.get()).contains("\"html\":true").contains("<p>Hello</p>");
        // Item 3: the plain-text alternative travels with it, for APIs that send multipart/alternative.
        assertThat(body.get()).contains("\"text\":\"Hello\"");
    }

    @Test
    void httpDriver_sendsTheGivenTextPart() {
        final AtomicReference<String> body = new AtomicReference<>();
        final HttpEmailDriver driver = new HttpEmailDriver((url, headers, payload) -> {
            body.set(payload);
            return 202;
        });

        driver.send(new ResolvedProviderDto("EMAIL", "HTTP", "no-reply@helix.test", "Helix", Map.of("url", "https://e/send"),
                null), "ada@helix.test", "Hi", "<p>x</p>", true, "Verify: https://idp/v?t=1");

        assertThat(body.get()).contains("\"text\":\"Verify: https://idp/v?t=1\"");
    }

    @Test
    void httpDriver_plainEmail_textIsTheBody() {
        final AtomicReference<String> body = new AtomicReference<>();
        final HttpEmailDriver driver = new HttpEmailDriver((url, headers, payload) -> {
            body.set(payload);
            return 202;
        });

        driver.send(new ResolvedProviderDto("EMAIL", "HTTP", "no-reply@helix.test", "Helix", Map.of("url", "https://e/send"),
                null), "ada@helix.test", "Hi", "Your code: 1", false);

        assertThat(body.get()).contains("\"text\":\"Your code: 1\"").contains("\"html\":false");
    }
}
