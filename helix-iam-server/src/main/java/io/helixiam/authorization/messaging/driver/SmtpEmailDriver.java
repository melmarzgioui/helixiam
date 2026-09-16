/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.driver;

import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import jakarta.mail.Message;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Properties;

/**
 * Helix IAM notifications (N3): SMTP email driver (Jakarta Mail). {@code config.host}/{@code config.port}/
 * {@code config.username}/{@code config.starttls}, {@code provider.fromAddress}/{@code fromName}, and
 * {@code secret} = the SMTP password. The actual {@code Transport.send} goes through {@link MailTransport} so
 * the driver is unit-testable without a mail server.
 */
@Component
public class SmtpEmailDriver implements EmailDriver {

    /** Seam over {@code Transport.send} so tests capture the message instead of dialing SMTP. */
    public interface MailTransport {
        void send(Session session, MimeMessage message, String username, String password) throws Exception;
    }

    private final MailTransport transport;

    public SmtpEmailDriver() {
        this(defaultTransport());
    }

    public SmtpEmailDriver(final MailTransport transport) {
        this.transport = transport;
    }

    @Override
    public String driver() {
        return "SMTP";
    }

    @Override
    public void send(final ResolvedProviderDto provider, final String to, final String subject, final String body,
                     final boolean html) {
        final Map<String, String> config = provider.config() == null ? Map.of() : provider.config();
        final String host = config.get("host");
        if (host == null || host.isBlank()) {
            throw new IllegalStateException("SMTP email provider is missing host");
        }
        final String port = config.getOrDefault("port", "587");
        final boolean starttls = !"false".equalsIgnoreCase(config.getOrDefault("starttls", "true"));
        final String username = config.get("username");

        final Properties props = new Properties();
        props.put("mail.smtp.host", host);
        props.put("mail.smtp.port", port);
        props.put("mail.smtp.auth", username != null && !username.isBlank() ? "true" : "false");
        props.put("mail.smtp.starttls.enable", String.valueOf(starttls));
        final Session session = Session.getInstance(props);

        try {
            final MimeMessage message = new MimeMessage(session);
            final String fromName = provider.fromName();
            message.setFrom(fromName != null && !fromName.isBlank()
                    ? new InternetAddress(provider.fromAddress(), fromName) : new InternetAddress(provider.fromAddress()));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
            message.setSubject(subject == null ? "" : subject);
            if (html) {
                message.setContent(body == null ? "" : body, "text/html; charset=UTF-8");
            } else {
                message.setText(body == null ? "" : body, "UTF-8");
            }
            message.saveChanges(); // flush headers (Content-Type/MIME-Version) before handing to the transport
            transport.send(session, message, username, provider.secret());
        } catch (final Exception e) {
            throw new IllegalStateException("SMTP send failed: " + e.getMessage(), e);
        }
    }

    private static MailTransport defaultTransport() {
        return (session, message, username, password) -> {
            try (Transport t = session.getTransport("smtp")) {
                if (username != null && !username.isBlank()) {
                    t.connect(username, password);
                } else {
                    t.connect();
                }
                t.sendMessage(message, message.getAllRecipients());
            }
        };
    }
}
