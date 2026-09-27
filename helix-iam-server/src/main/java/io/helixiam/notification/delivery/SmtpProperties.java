/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

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
    /** Blank = 587, or 465 with {@code tls-mode=IMPLICIT}. */
    private Integer port;
    private String username;
    private String password;
    /** A file holding the password (a mounted secret); read at every send, wins over {@code password}. */
    private String passwordFile;
    /** Deprecated: use {@code tls-mode} ({@code true} = STARTTLS_REQUIRED, {@code false} = STARTTLS_OPTIONAL). */
    private boolean starttls = true;
    /** {@code STARTTLS_REQUIRED} (default), {@code STARTTLS_OPTIONAL}, {@code IMPLICIT} or {@code NONE} (dev only). */
    private String tlsMode;
    private java.time.Duration connectTimeout;
    private java.time.Duration readTimeout;
    /** The EHLO name; blank = the local host name. */
    private String ehloName;
    /** A PEM file of CA certificates trusted in addition to the JDK roots (a private relay). */
    private String caBundleFile;
    private String fromAddress = "no-reply@helix.local";
    private String fromName = "HelixIAM";

    public String getHost() {
        return host;
    }

    public void setHost(final String host) {
        this.host = host;
    }

    public Integer getPort() {
        return port;
    }

    public void setPort(final Integer port) {
        this.port = port;
    }

    public String getPasswordFile() {
        return passwordFile;
    }

    public void setPasswordFile(final String passwordFile) {
        this.passwordFile = passwordFile;
    }

    public String getTlsMode() {
        return tlsMode;
    }

    public void setTlsMode(final String tlsMode) {
        this.tlsMode = tlsMode;
    }

    public java.time.Duration getConnectTimeout() {
        return connectTimeout;
    }

    public void setConnectTimeout(final java.time.Duration connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    public java.time.Duration getReadTimeout() {
        return readTimeout;
    }

    public void setReadTimeout(final java.time.Duration readTimeout) {
        this.readTimeout = readTimeout;
    }

    public String getEhloName() {
        return ehloName;
    }

    public void setEhloName(final String ehloName) {
        this.ehloName = ehloName;
    }

    public String getCaBundleFile() {
        return caBundleFile;
    }

    public void setCaBundleFile(final String caBundleFile) {
        this.caBundleFile = caBundleFile;
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

    @Override
    public String toString() {
        return "SmtpProperties[host=" + host + ", port=" + port + ", username=" + username + ", password="
                + (password == null ? "unset" : "***") + ", tlsMode=" + tlsMode + "]";
    }
}
