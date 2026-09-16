package io.helixiam.authorization.messaging.driver;

import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import jakarta.mail.internet.MimeMessage;
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

        assertThat(captured.get().getContentType()).contains("text/html");
        assertThat((String) captured.get().getContent()).isEqualTo("<h1>Hello</h1>");
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
    }
}
