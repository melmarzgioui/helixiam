package io.helixiam.notification.delivery;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Task 4 (strip-RabbitMQ notification delivery). Global SMTP fallback for {@link SmtpNotifier}, used
 * only when the in-flight realm has no enabled {@code EMAIL} messaging provider (Realm Settings &gt;
 * Messaging &gt; Providers — see {@code io.helixiam.authorization.domain.messaging.MessagingProvider}).
 * Deliberately a plain custom {@code @ConfigurationProperties} (prefix {@code helix.notification.smtp})
 * rather than Spring Boot's {@code spring.mail.*} + {@code JavaMailSender}: the pom already carries
 * {@code jakarta.mail-api}/{@code angus-mail} for the realm messaging feature's
 * {@code SmtpEmailDriver}, and reusing that one Jakarta Mail code path (instead of adding
 * {@code spring-boot-starter-mail} for a second one) keeps SMTP wire-level sending in a single place.
 */
@ConfigurationProperties(prefix = "helix.notification.smtp")
public class SmtpProperties {

    /** Blank = no global fallback configured; {@link SmtpNotifier} then only delivers via a realm provider. */
    private String host;
    private int port = 587;
    private String username;
    private String password;
    private boolean starttls = true;
    private String fromAddress = "no-reply@helix.local";
    private String fromName = "HelixIAM";

    public String getHost() {
        return host;
    }

    public void setHost(final String host) {
        this.host = host;
    }

    public int getPort() {
        return port;
    }

    public void setPort(final int port) {
        this.port = port;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(final String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(final String password) {
        this.password = password;
    }

    public boolean isStarttls() {
        return starttls;
    }

    public void setStarttls(final boolean starttls) {
        this.starttls = starttls;
    }

    public String getFromAddress() {
        return fromAddress;
    }

    public void setFromAddress(final String fromAddress) {
        this.fromAddress = fromAddress;
    }

    public String getFromName() {
        return fromName;
    }

    public void setFromName(final String fromName) {
        this.fromName = fromName;
    }
}
