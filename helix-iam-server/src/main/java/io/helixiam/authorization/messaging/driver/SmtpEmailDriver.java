/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.driver;

import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.authorization.messaging.email.DeliveryResult;
import io.helixiam.authorization.messaging.email.DeliveryResult.Reason;
import io.helixiam.authorization.messaging.email.EmailAddress;
import io.helixiam.authorization.messaging.email.EmailMessage;
import io.helixiam.authorization.messaging.email.EmailTransport;
import io.helixiam.authorization.messaging.email.SmtpTlsMode;
import io.helixiam.authorization.messaging.email.TlsTrust;
import io.helixiam.common.startup.DeploymentProfile;
import jakarta.mail.AuthenticationFailedException;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The SMTP email transport (Jakarta Mail).
 *
 * <p>Settings ({@code provider.config()}): {@code host} (required), {@code port} (default 587, or 465 for
 * {@code IMPLICIT}), {@code username}, {@code tlsMode} ({@link SmtpTlsMode}; the deprecated boolean {@code starttls}
 * maps to it), {@code connectTimeoutMs} (default 10000), {@code readTimeoutMs} (default 20000), {@code ehloName} and
 * {@code caBundle} (PEM certificates trusted in addition to the JDK roots, for a private relay). The secret is the
 * SMTP password. Certificates and the server's host name are always verified.
 *
 * <p>Failures are classified: an SMTP 5xx reply is permanent (a 5xx on a recipient is a bounce); a 4xx reply, a
 * connection, timeout or TLS error is transient.
 *
 * <p>The wire-level send goes through {@link MailTransport} so the MIME message can be inspected in a unit test.
 */
@Component
public class SmtpEmailDriver implements EmailTransport {

    /** Seam over {@code Transport.send} so tests capture the message instead of dialing SMTP. */
    public interface MailTransport {
        void send(Session session, MimeMessage message, String username, String password) throws Exception;
    }

    public static final String DRIVER = "SMTP";
    static final int DEFAULT_CONNECT_TIMEOUT_MS = 10_000;
    static final int DEFAULT_READ_TIMEOUT_MS = 20_000;
    private static final Pattern REPLY_CODE = Pattern.compile("^\\s*([245]\\d\\d)[\\s-]");

    private final MailTransport transport;
    private final DeploymentProfile profile;

    @Autowired
    public SmtpEmailDriver(final DeploymentProfile profile) {
        this(defaultTransport(), profile);
    }

    /** A driver in production mode over {@code transport} (tests). */
    public SmtpEmailDriver(final MailTransport transport) {
        this(transport, DeploymentProfile.production());
    }

    public SmtpEmailDriver(final MailTransport transport, final DeploymentProfile profile) {
        this.transport = transport;
        this.profile = profile == null ? DeploymentProfile.production() : profile;
    }

    /** The real SMTP transport (tests that talk to a local SMTP server use it). */
    public static MailTransport defaultTransport() {
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

    @Override
    public String driver() {
        return DRIVER;
    }

    @Override
    public DeliveryResult deliver(final ResolvedProviderDto provider, final EmailMessage input) {
        final Map<String, String> config = provider.config() == null ? Map.of() : provider.config();
        final Settings settings;
        final Properties props;
        try {
            settings = Settings.of(config);
            props = settings.sessionProperties();
        } catch (final IllegalArgumentException e) {
            return DeliveryResult.permanent(Reason.CONFIGURATION, "SMTP settings: " + e.getMessage());
        }
        if (settings.tlsMode() == SmtpTlsMode.NONE && !profile.isDev()) {
            return DeliveryResult.permanent(Reason.CONFIGURATION,
                    "tlsMode NONE (plain-text SMTP) is only allowed with the dev profile");
        }
        final EmailMessage message = input.withDefaultFrom(provider.fromAddress(), provider.fromName());
        if (message.from() == null) {
            return DeliveryResult.permanent(Reason.CONFIGURATION, "The email provider has no from address");
        }
        final Session session = Session.getInstance(props);
        final MimeMessage mime;
        try {
            mime = mime(session, message);
        } catch (final AddressException | UnsupportedEncodingException | IllegalArgumentException e) {
            return DeliveryResult.permanent(Reason.MESSAGE_REJECTED, "An address of the email is not valid");
        } catch (final MessagingException e) {
            return DeliveryResult.permanent(Reason.MESSAGE_REJECTED, "The email could not be built");
        }
        try {
            transport.send(session, mime, settings.username(), provider.secret());
        } catch (final Exception e) {
            return classify(e, message);
        }
        String id = null;
        try {
            id = mime.getMessageID();
        } catch (final MessagingException ignored) {
            // no id: fine
        }
        return DeliveryResult.accepted(id, "Accepted by " + settings.host() + ":" + settings.port()
                + " (" + settings.tlsMode() + ")");
    }

    /** The MIME message: {@code multipart/alternative} (text first, then HTML) for an HTML email. */
    private static MimeMessage mime(final Session session, final EmailMessage message)
            throws MessagingException, UnsupportedEncodingException {
        final String domain = domainOf(message.from().address());
        final MimeMessage mime = new MimeMessage(session) {
            @Override
            protected void updateMessageID() throws MessagingException {
                // Stable across retries: the same logical email always carries the same Message-ID.
                setHeader("Message-ID", "<" + message.messageId() + "@" + domain + ">");
            }
        };
        mime.setFrom(address(message.from()));
        final InternetAddress[] to = new InternetAddress[message.to().size()];
        for (int i = 0; i < to.length; i++) {
            to[i] = address(message.to().get(i));
        }
        mime.setRecipients(Message.RecipientType.TO, to);
        if (message.replyTo() != null) {
            mime.setReplyTo(new InternetAddress[] {address(message.replyTo())});
        }
        mime.setSubject(message.subject(), "UTF-8");
        for (final Map.Entry<String, String> h : message.headers().entrySet()) {
            mime.setHeader(h.getKey(), h.getValue());
        }
        if (message.isHtml()) {
            final MimeBodyPart textPart = new MimeBodyPart();
            textPart.setText(message.text(), "UTF-8");
            final MimeBodyPart htmlPart = new MimeBodyPart();
            htmlPart.setContent(message.html(), "text/html; charset=UTF-8");
            final MimeMultipart alternative = new MimeMultipart("alternative");
            alternative.addBodyPart(textPart);
            alternative.addBodyPart(htmlPart);
            mime.setContent(alternative);
        } else {
            mime.setText(message.text(), "UTF-8");
        }
        mime.saveChanges(); // flush headers (Content-Type/MIME-Version/Message-ID) before handing to the transport
        return mime;
    }

    private static InternetAddress address(final EmailAddress a) throws AddressException, UnsupportedEncodingException {
        final InternetAddress parsed = new InternetAddress(a.address(), true);
        if (a.name() != null) {
            parsed.setPersonal(a.name(), "UTF-8");
        }
        return parsed;
    }

    private static String domainOf(final String address) {
        final int at = address.lastIndexOf('@');
        final String domain = at >= 0 ? address.substring(at + 1) : "";
        return domain.matches("[A-Za-z0-9.-]+") ? domain : "helixiam.invalid";
    }

    /**
     * Classifies a failed send: an SMTP 5xx reply is permanent (on a recipient: a bounce), a 4xx reply is transient,
     * and a connection, timeout or TLS error is transient.
     */
    static DeliveryResult classify(final Throwable failure, final EmailMessage message) {
        for (Throwable t = failure; t != null; t = next(t)) {
            if (t instanceof org.eclipse.angus.mail.smtp.SMTPAddressFailedException af) {
                return byCode(af.getReturnCode(), true, af.getMessage(), message);
            }
            if (t instanceof org.eclipse.angus.mail.smtp.SMTPSenderFailedException sf) {
                return byCode(sf.getReturnCode(), false, sf.getMessage(), message);
            }
        }
        for (Throwable t = failure; t != null; t = next(t)) {
            if (t instanceof org.eclipse.angus.mail.smtp.SMTPSendFailedException sf && sf.getReturnCode() > 0) {
                return byCode(sf.getReturnCode(), false, sf.getMessage(), message);
            }
            if (t instanceof AuthenticationFailedException) {
                final int code = replyCode(t.getMessage());
                return code >= 400 && code < 500
                        ? DeliveryResult.transientFailure(Reason.AUTHENTICATION, "SMTP authentication failed (" + code + ")")
                        : DeliveryResult.permanent(Reason.AUTHENTICATION,
                        "SMTP authentication failed" + (code > 0 ? " (" + code + ")" : ""));
            }
            if (t instanceof SSLException || t instanceof CertificateException) {
                return DeliveryResult.transientFailure(Reason.NETWORK,
                        "TLS handshake with the SMTP server failed (certificate or protocol)");
            }
            if (t instanceof UnknownHostException) {
                return DeliveryResult.transientFailure(Reason.NETWORK, "The SMTP host could not be resolved");
            }
            if (t instanceof SocketTimeoutException) {
                return DeliveryResult.transientFailure(Reason.NETWORK, "The SMTP server timed out");
            }
            if (t instanceof ConnectException || t instanceof org.eclipse.angus.mail.util.MailConnectException) {
                return DeliveryResult.transientFailure(Reason.NETWORK, "Could not connect to the SMTP server");
            }
            final String msg = t.getMessage() == null ? "" : t.getMessage();
            if (msg.contains("STARTTLS is required")) {
                return DeliveryResult.transientFailure(Reason.CONFIGURATION,
                        "The SMTP server does not offer STARTTLS, which tlsMode STARTTLS_REQUIRED requires");
            }
        }
        for (Throwable t = failure; t != null; t = next(t)) {
            final int code = replyCode(t.getMessage());
            if (code >= 400) {
                return byCode(code, false, t.getMessage(), message);
            }
            if (t instanceof IOException) {
                return DeliveryResult.transientFailure(Reason.NETWORK, "The SMTP connection failed");
            }
        }
        return DeliveryResult.transientFailure(Reason.PROVIDER_ERROR,
                "SMTP send failed (" + failure.getClass().getSimpleName() + ")");
    }

    private static Throwable next(final Throwable t) {
        final Throwable cause = t instanceof MessagingException me && me.getNextException() != null
                ? me.getNextException() : t.getCause();
        return cause == t ? null : cause;
    }

    private static DeliveryResult byCode(final int code, final boolean recipient, final String reply,
                                         final EmailMessage message) {
        final String diagnostic = "SMTP " + code + replyText(reply);
        if (code >= 500 && code < 600) {
            return recipient
                    ? DeliveryResult.bounced(List.of(message.primaryRecipient().address()), diagnostic)
                    : DeliveryResult.permanent(Reason.MESSAGE_REJECTED, diagnostic);
        }
        if (code == 450 || code == 451 || code == 452) {
            return DeliveryResult.transientFailure(Reason.RATE_LIMITED, diagnostic);
        }
        return DeliveryResult.transientFailure(Reason.PROVIDER_ERROR, diagnostic);
    }

    /** The server's reply text after the code (first line, capped): it names the problem, never our secret. */
    private static String replyText(final String reply) {
        if (reply == null) {
            return "";
        }
        final String line = reply.lines().findFirst().orElse("").trim();
        final Matcher m = REPLY_CODE.matcher(line + " ");
        final String text = m.find() ? line.substring(Math.min(line.length(), m.end(1))).trim() : line;
        if (text.isEmpty()) {
            return "";
        }
        return ": " + (text.length() > 160 ? text.substring(0, 160) + "…" : text);
    }

    private static int replyCode(final String message) {
        if (message == null) {
            return -1;
        }
        final Matcher m = REPLY_CODE.matcher(message + " ");
        return m.find() ? Integer.parseInt(m.group(1)) : -1;
    }

    /** The parsed, validated SMTP settings of a provider. */
    public record Settings(String host, int port, String username, SmtpTlsMode tlsMode, int connectTimeoutMs,
                           int readTimeoutMs, String ehloName, String caBundle) {

        /**
         * Parses the provider config.
         *
         * @throws IllegalArgumentException naming the first invalid setting
         */
        public static Settings of(final Map<String, String> config) {
            final String host = blankToNull(config.get("host"));
            if (host == null) {
                throw new IllegalArgumentException("host is required");
            }
            if (!host.matches("[A-Za-z0-9.:\\[\\]_-]+")) {
                throw new IllegalArgumentException("host is not a host name or address");
            }
            final SmtpTlsMode mode = SmtpTlsMode.resolve(config.get("tlsMode"), config.get("starttls"));
            final int port = intSetting(config, "port", mode.defaultPort(), 1, 65535);
            final int connect = intSetting(config, "connectTimeoutMs", DEFAULT_CONNECT_TIMEOUT_MS, 100, 300_000);
            final int read = intSetting(config, "readTimeoutMs", DEFAULT_READ_TIMEOUT_MS, 100, 300_000);
            final String ehlo = blankToNull(config.get("ehloName"));
            if (ehlo != null && !ehlo.matches("[A-Za-z0-9.-]{1,253}")) {
                throw new IllegalArgumentException("ehloName is not a host name");
            }
            final String caBundle = blankToNull(config.get("caBundle"));
            if (caBundle != null) {
                TlsTrust.parse(caBundle);
            }
            return new Settings(host, port, blankToNull(config.get("username")), mode, connect, read, ehlo, caBundle);
        }

        Properties sessionProperties() {
            final Properties props = new Properties();
            props.put("mail.smtp.host", host);
            props.put("mail.smtp.port", String.valueOf(port));
            props.put("mail.smtp.auth", String.valueOf(username != null));
            props.put("mail.smtp.connectiontimeout", String.valueOf(connectTimeoutMs));
            props.put("mail.smtp.timeout", String.valueOf(readTimeoutMs));
            props.put("mail.smtp.writetimeout", String.valueOf(readTimeoutMs));
            if (ehloName != null) {
                props.put("mail.smtp.localhost", ehloName);
            }
            switch (tlsMode) {
                case IMPLICIT -> props.put("mail.smtp.ssl.enable", "true");
                case STARTTLS_REQUIRED -> {
                    props.put("mail.smtp.starttls.enable", "true");
                    props.put("mail.smtp.starttls.required", "true");
                }
                case STARTTLS_OPTIONAL -> props.put("mail.smtp.starttls.enable", "true");
                case NONE -> props.put("mail.smtp.starttls.enable", "false");
                default -> throw new IllegalStateException();
            }
            // Always verify: the JDK roots (+ the optional CA bundle) and the server's host name. No "trust all".
            props.put("mail.smtp.ssl.checkserveridentity", "true");
            props.put("mail.smtp.ssl.protocols", "TLSv1.3 TLSv1.2");
            props.put("mail.smtp.ssl.socketFactory", TlsTrust.context(caBundle).getSocketFactory());
            return props;
        }

        private static int intSetting(final Map<String, String> config, final String key, final int dflt,
                                      final int min, final int max) {
            final String raw = blankToNull(config.get(key));
            if (raw == null) {
                return dflt;
            }
            final int v;
            try {
                v = Integer.parseInt(raw);
            } catch (final NumberFormatException e) {
                throw new IllegalArgumentException(key + " must be a number");
            }
            if (v < min || v > max) {
                throw new IllegalArgumentException(key + " must be between " + min + " and " + max);
            }
            return v;
        }

        private static String blankToNull(final String v) {
            return v == null || v.isBlank() ? null : v.trim();
        }
    }
}
