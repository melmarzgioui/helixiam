/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.messaging.MessagingProviderWriteDto;
import io.helixiam.authorization.controller.admin.io.SecretMasking;
import io.helixiam.authorization.messaging.email.SmtpTlsMode;
import io.helixiam.authorization.messaging.email.TlsTrust;
import io.helixiam.common.startup.DeploymentProfile;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Validates a messaging provider before it is saved ({@code PUT /admin/realms/{r}/messaging/providers}): a known
 * channel and driver, and for email the from address and each driver's required settings (SMTP host, port range and
 * TLS mode; Cloudflare account id, API token and an {@code https} base URL; HTTP url; the optional
 * {@code sendLimitPerMinute} rate cap of any email driver). The realm import applies the same checks. Failures are a
 * {@link ProviderValidationException} (400 {@code {message, fieldErrors}}). Settings that are only safe for local
 * development ({@code tlsMode: NONE}, an {@code http://} Cloudflare base URL) are refused unless the server runs with
 * the {@code dev} profile.
 *
 * <p>An email credential given in {@code config} ({@code password} for SMTP, {@code apiToken} for Cloudflare) is moved
 * to the write-only {@code secret}, so it is stored encrypted and never returned; any other secret-looking config key
 * is refused for email.
 */
@Component
public class MessagingProviderValidator {

    static final Map<String, Set<String>> DRIVERS = Map.of(
            "EMAIL", Set.of("SMTP", "CLOUDFLARE", "HTTP", "LOG"),
            "SMS", Set.of("TWILIO", "HTTP"),
            "PUSH", Set.of("FCM", "APNS"));

    private final DeploymentProfile profile;

    public MessagingProviderValidator(final DeploymentProfile profile) {
        this.profile = profile;
    }

    /**
     * The provider to save (with an email credential moved from {@code config} to {@code secret}).
     *
     * @param secretStored whether this provider already has a stored secret (a blank {@code secret} keeps it)
     * @throws ProviderValidationException with one message per invalid field
     */
    public MessagingProviderWriteDto validate(final MessagingProviderWriteDto write, final boolean secretStored) {
        final Map<String, String> errors = new LinkedHashMap<>();
        final String channel = upper(write.channel());
        final String driver = upper(write.driver());
        final Set<String> drivers = DRIVERS.get(channel);
        if (drivers == null) {
            errors.put("channel", "Unknown channel. Use SMS, EMAIL or PUSH.");
            throw new ProviderValidationException(errors);
        }
        if (!drivers.contains(driver)) {
            errors.put("driver", "Unknown " + channel + " driver. Use " + String.join(", ", drivers.stream().sorted().toList())
                    + ".");
            throw new ProviderValidationException(errors);
        }
        final boolean clear = write.clearsSecret();
        if (clear && write.secret() != null && !write.secret().isBlank()) {
            errors.put("clearSecret", "Give a new secret or clear the stored one, not both.");
            throw new ProviderValidationException(errors);
        }
        if (!"EMAIL".equals(channel)) {
            return write;
        }
        final Map<String, String> config = new LinkedHashMap<>();
        if (write.config() != null) {
            write.config().forEach((k, v) -> {
                if (k != null && v != null && !v.isBlank()) {
                    config.put(k, v.trim());
                }
            });
        }
        String secret = write.secret();
        final String alias = "SMTP".equals(driver) ? "password" : "CLOUDFLARE".equals(driver) ? "apiToken" : null;
        if (alias != null && config.containsKey(alias)) {
            final String moved = config.remove(alias);
            if (clear) {
                errors.put("clearSecret", "Give a new secret or clear the stored one, not both.");
                throw new ProviderValidationException(errors);
            }
            if (secret == null || secret.isBlank()) {
                secret = moved;
            }
        }
        for (final String key : config.keySet()) {
            if (SecretMasking.isSecretKey(key) && !"authScheme".equals(key)) {
                errors.put("config." + key, "Put credentials in secret: it is stored encrypted and never returned.");
            }
        }
        if (!"LOG".equals(driver)) {
            checkFrom(write.fromAddress(), write.fromName(), errors);
        }
        // The realm's own send rate cap (emails per minute), instead of helix.notification.email.rate-limit.realm-per-minute.
        checkInt(config, "sendLimitPerMinute", 1, 1_000_000, "Enter a limit between 1 and 1000000 emails per minute.",
                errors);
        final boolean hasSecret = (secret != null && !secret.isBlank()) || (secretStored && !clear);
        switch (driver) {
            case "SMTP" -> checkSmtp(config, errors);
            case "CLOUDFLARE" -> checkCloudflare(config, hasSecret || !write.enabled(), errors);
            case "HTTP" -> checkUrl(config.get("url"), "config.url", false, errors);
            default -> { }
        }
        if (!errors.isEmpty()) {
            throw new ProviderValidationException(errors);
        }
        return new MessagingProviderWriteDto(write.realmId(), write.channel(), write.driver(), write.enabled(),
                write.fromAddress(), write.fromName(), config, secret, write.clearSecret());
    }

    private void checkSmtp(final Map<String, String> config, final Map<String, String> errors) {
        final String host = config.get("host");
        if (host == null) {
            errors.put("config.host", "The SMTP host is required.");
        } else if (!host.matches("[A-Za-z0-9.:\\[\\]_-]+")) {
            errors.put("config.host", "Enter a host name or IP address.");
        }
        SmtpTlsMode mode = null;
        try {
            mode = SmtpTlsMode.resolve(config.get("tlsMode"), config.get("starttls"));
        } catch (final IllegalArgumentException e) {
            errors.put(config.containsKey("tlsMode") ? "config.tlsMode" : "config.starttls", e.getMessage() + ".");
        }
        if (mode == SmtpTlsMode.NONE && !profile.isDev()) {
            errors.put("config.tlsMode", "tlsMode NONE (plain-text SMTP) is only allowed with the dev profile.");
        }
        checkInt(config, "port", 1, 65535, "Enter a port between 1 and 65535.", errors);
        checkInt(config, "connectTimeoutMs", 100, 300_000, "Enter a timeout between 100 and 300000 ms.", errors);
        checkInt(config, "readTimeoutMs", 100, 300_000, "Enter a timeout between 100 and 300000 ms.", errors);
        final String ehlo = config.get("ehloName");
        if (ehlo != null && !ehlo.matches("[A-Za-z0-9.-]{1,253}")) {
            errors.put("config.ehloName", "Enter a host name.");
        }
        checkCaBundle(config, errors);
    }

    private void checkCloudflare(final Map<String, String> config, final boolean hasSecret,
                                 final Map<String, String> errors) {
        final String account = config.get("accountId");
        if (account == null) {
            errors.put("config.accountId", "The Cloudflare account id is required.");
        } else if (!account.matches("[A-Za-z0-9_-]{1,64}")) {
            errors.put("config.accountId", "The account id is letters and digits.");
        }
        if (!hasSecret) {
            errors.put("secret", "The Cloudflare API token is required to enable this provider.");
        }
        if (config.containsKey("baseUrl")) {
            checkUrl(config.get("baseUrl"), "config.baseUrl", true, errors);
        }
        checkInt(config, "connectTimeoutMs", 100, 300_000, "Enter a timeout between 100 and 300000 ms.", errors);
        checkInt(config, "readTimeoutMs", 100, 300_000, "Enter a timeout between 100 and 300000 ms.", errors);
        checkCaBundle(config, errors);
    }

    private void checkUrl(final String url, final String field, final boolean httpsOnly,
                          final Map<String, String> errors) {
        if (url == null) {
            errors.put(field, "The URL is required.");
            return;
        }
        final URI uri;
        try {
            uri = new URI(url);
        } catch (final URISyntaxException e) {
            errors.put(field, "Enter a valid URL.");
            return;
        }
        final String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (uri.getHost() == null || !("https".equals(scheme) || "http".equals(scheme))) {
            errors.put(field, "Enter an absolute http(s) URL.");
        } else if (uri.getRawUserInfo() != null) {
            errors.put(field, "Do not put credentials in the URL; use secret.");
        } else if (httpsOnly && !"https".equals(scheme) && !profile.isDev()) {
            errors.put(field, "The URL must use https.");
        } else if (httpsOnly && (uri.getRawQuery() != null || uri.getRawFragment() != null)) {
            errors.put(field, "The base URL cannot have a query or fragment.");
        }
    }

    private static void checkFrom(final String fromAddress, final String fromName, final Map<String, String> errors) {
        if (fromAddress == null || fromAddress.isBlank()) {
            errors.put("fromAddress", "The from address is required.");
        } else {
            try {
                final InternetAddress a = new InternetAddress(fromAddress.trim(), true);
                if (!a.getAddress().contains("@") || !a.getAddress().equals(fromAddress.trim())) {
                    errors.put("fromAddress", "Enter a single email address, like no-reply@example.com.");
                }
            } catch (final AddressException e) {
                errors.put("fromAddress", "Enter a single email address, like no-reply@example.com.");
            }
        }
        if (fromName != null && (fromName.indexOf('\r') >= 0 || fromName.indexOf('\n') >= 0 || fromName.length() > 200)) {
            errors.put("fromName", "The from name is one line of at most 200 characters.");
        }
    }

    private static void checkCaBundle(final Map<String, String> config, final Map<String, String> errors) {
        final String bundle = config.get("caBundle");
        if (bundle != null) {
            try {
                TlsTrust.parse(bundle);
            } catch (final IllegalArgumentException e) {
                errors.put("config.caBundle", "Paste one or more PEM certificates (-----BEGIN CERTIFICATE-----).");
            }
        }
    }

    private static void checkInt(final Map<String, String> config, final String key, final int min, final int max,
                                 final String message, final Map<String, String> errors) {
        final String raw = config.get(key);
        if (raw == null) {
            return;
        }
        try {
            final int v = Integer.parseInt(raw);
            if (v < min || v > max) {
                errors.put("config." + key, message);
            }
        } catch (final NumberFormatException e) {
            errors.put("config." + key, message);
        }
    }

    private static String upper(final String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }
}
