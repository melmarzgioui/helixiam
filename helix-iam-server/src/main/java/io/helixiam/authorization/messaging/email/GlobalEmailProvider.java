/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.authorization.messaging.driver.CloudflareEmailDriver;
import io.helixiam.authorization.messaging.driver.LogEmailDriver;
import io.helixiam.authorization.messaging.driver.SmtpEmailDriver;
import io.helixiam.common.log.LogSafe;
import io.helixiam.notification.delivery.SmtpProperties;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * The server-wide default email provider ({@code helix.notification.email.driver}: {@code smtp}, {@code cloudflare}
 * or {@code log}), built from the properties at every call: secrets given as files ({@code password-file},
 * {@code api-token-file}) are read fresh, so rotating them needs no restart.
 */
public class GlobalEmailProvider {

    private static final Logger LOG = LogManager.getLogger(GlobalEmailProvider.class);
    private static final String CHANNEL = "EMAIL";

    private final EmailProperties email;
    private final SmtpProperties smtp;
    private final CloudflareProperties cloudflare;

    public GlobalEmailProvider(final EmailProperties email, final SmtpProperties smtp,
                               final CloudflareProperties cloudflare) {
        this.email = email == null ? new EmailProperties() : email;
        this.smtp = smtp == null ? new SmtpProperties() : smtp;
        this.cloudflare = cloudflare == null ? new CloudflareProperties() : cloudflare;
    }

    /** The configured global provider, or empty when the selected driver is not configured. */
    public Optional<ResolvedProviderDto> resolve() {
        final String driver = email.getDriver() == null || email.getDriver().isBlank()
                ? "smtp" : email.getDriver().trim().toLowerCase(Locale.ROOT);
        return switch (driver) {
            case "smtp" -> smtp();
            case "cloudflare" -> cloudflare();
            case "log" -> Optional.of(new ResolvedProviderDto(CHANNEL, LogEmailDriver.DRIVER, fromAddress(), fromName(),
                    Map.of(), null));
            default -> {
                LOG.warn("Unknown helix.notification.email.driver {}; use smtp, cloudflare or log",
                        LogSafe.sanitize(driver));
                yield Optional.empty();
            }
        };
    }

    private Optional<ResolvedProviderDto> smtp() {
        if (smtp.getHost() == null || smtp.getHost().isBlank()) {
            return Optional.empty();
        }
        final Map<String, String> config = new LinkedHashMap<>();
        config.put("host", smtp.getHost().trim());
        if (smtp.getPort() != null) {
            config.put("port", String.valueOf(smtp.getPort()));
        }
        config.put("username", smtp.getUsername() == null ? "" : smtp.getUsername());
        config.put("starttls", String.valueOf(smtp.isStarttls()));
        putIfSet(config, "tlsMode", smtp.getTlsMode());
        putIfSet(config, "connectTimeoutMs", millis(smtp.getConnectTimeout()));
        putIfSet(config, "readTimeoutMs", millis(smtp.getReadTimeout()));
        putIfSet(config, "ehloName", smtp.getEhloName());
        if (smtp.getCaBundleFile() != null && !smtp.getCaBundleFile().isBlank()) {
            putIfSet(config, "caBundle", SecretFiles.read(smtp.getCaBundleFile(), "SMTP CA bundle"));
        }
        final String password = SecretFiles.valueOrFile(smtp.getPassword(), smtp.getPasswordFile(), "SMTP password");
        return Optional.of(new ResolvedProviderDto(CHANNEL, SmtpEmailDriver.DRIVER, fromAddress(), fromName(), config,
                password));
    }

    private Optional<ResolvedProviderDto> cloudflare() {
        final String token = SecretFiles.valueOrFile(cloudflare.getApiToken(), cloudflare.getApiTokenFile(),
                "Cloudflare API token");
        if (cloudflare.getAccountId() == null || cloudflare.getAccountId().isBlank() || token == null) {
            LOG.warn("helix.notification.email.driver=cloudflare needs helix.notification.cloudflare.account-id and "
                    + "api-token (or api-token-file)");
            return Optional.empty();
        }
        final Map<String, String> config = new LinkedHashMap<>();
        config.put("accountId", cloudflare.getAccountId().trim());
        putIfSet(config, "baseUrl", cloudflare.getBaseUrl());
        putIfSet(config, "connectTimeoutMs", millis(cloudflare.getConnectTimeout()));
        putIfSet(config, "readTimeoutMs", millis(cloudflare.getReadTimeout()));
        if (cloudflare.getCaBundleFile() != null && !cloudflare.getCaBundleFile().isBlank()) {
            putIfSet(config, "caBundle", SecretFiles.read(cloudflare.getCaBundleFile(), "Cloudflare CA bundle"));
        }
        return Optional.of(new ResolvedProviderDto(CHANNEL, CloudflareEmailDriver.DRIVER, fromAddress(), fromName(),
                config, token));
    }

    private String fromAddress() {
        return email.getFromAddress() != null && !email.getFromAddress().isBlank()
                ? email.getFromAddress() : smtp.getFromAddress();
    }

    private String fromName() {
        return email.getFromName() != null && !email.getFromName().isBlank() ? email.getFromName() : smtp.getFromName();
    }

    private static String millis(final Duration d) {
        return d == null ? null : String.valueOf(d.toMillis());
    }

    private static void putIfSet(final Map<String, String> config, final String key, final String value) {
        if (value != null && !value.isBlank()) {
            config.put(key, value.trim());
        }
    }
}
