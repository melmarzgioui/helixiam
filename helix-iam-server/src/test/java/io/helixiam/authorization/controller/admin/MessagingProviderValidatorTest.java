/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.messaging.MessagingProviderWriteDto;
import io.helixiam.common.startup.DeploymentProfile;
import io.helixiam.testsupport.TestTls;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Validation of a messaging provider before it is saved: unknown drivers and missing or unsafe settings are refused. */
class MessagingProviderValidatorTest {

    private final MessagingProviderValidator prod = new MessagingProviderValidator(DeploymentProfile.production());
    private final MessagingProviderValidator dev = new MessagingProviderValidator(DeploymentProfile.development());

    private static MessagingProviderWriteDto email(final String driver, final Map<String, String> config,
                                                   final String secret) {
        return new MessagingProviderWriteDto("acme", "EMAIL", driver, true, "no-reply@example.com", "Acme",
                config, secret);
    }

    private static Map<String, String> errors(final Runnable call) {
        try {
            call.run();
        } catch (final ProviderValidationException e) {
            return e.fieldErrors();
        }
        throw new AssertionError("expected a validation error");
    }

    @Test
    void unknownDriversAndChannels_areRefused() {
        assertThat(errors(() -> prod.validate(email("SES", Map.of(), null), false))).containsOnlyKeys("driver");
        assertThat(errors(() -> prod.validate(email("sendgrid", Map.of(), null), false)).get("driver"))
                .contains("CLOUDFLARE").contains("SMTP").contains("HTTP").contains("LOG");
        assertThat(errors(() -> prod.validate(new MessagingProviderWriteDto("acme", "FAX", "HTTP", true, null, null,
                Map.of(), null), false))).containsOnlyKeys("channel");
        assertThat(errors(() -> prod.validate(new MessagingProviderWriteDto("acme", "SMS", "SMTP", true, null, null,
                Map.of(), null), false))).containsOnlyKeys("driver");
    }

    @Test
    void theKnownDrivers_areAccepted_caseInsensitively() {
        prod.validate(email("smtp", Map.of("host", "smtp.example.com"), "pw"), false);
        prod.validate(email("CLOUDFLARE", Map.of("accountId", "abc123"), "token"), false);
        prod.validate(email("HTTP", Map.of("url", "http://relay.example.com/send"), null), false);
        prod.validate(new MessagingProviderWriteDto("acme", "EMAIL", "LOG", true, null, null, Map.of(), null), false);
        prod.validate(new MessagingProviderWriteDto("acme", "SMS", "TWILIO", true, "+15550100", null,
                Map.of("accountSid", "AC1"), "t"), false);
        prod.validate(new MessagingProviderWriteDto("acme", "PUSH", "FCM", true, null, null, Map.of(), "{}"), false);
    }

    @Test
    void smtp_requiresAHostAndAFromAddress_andChecksPortAndTlsMode() {
        final Map<String, String> e = errors(() -> prod.validate(new MessagingProviderWriteDto("acme", "EMAIL", "SMTP",
                true, " ", null, Map.of("port", "70000", "tlsMode", "SSL"), null), false));
        assertThat(e).containsKeys("fromAddress", "config.host", "config.port", "config.tlsMode");

        assertThat(errors(() -> prod.validate(email("SMTP", Map.of("host", "smtp.example.com", "starttls", "maybe"),
                null), false))).containsOnlyKeys("config.starttls");
        assertThat(errors(() -> prod.validate(email("SMTP", Map.of("host", "smtp.example.com",
                "caBundle", "not pem"), null), false))).containsOnlyKeys("config.caBundle");
        prod.validate(email("SMTP", Map.of("host", "smtp.example.com", "tlsMode", "IMPLICIT", "port", "465",
                "caBundle", TestTls.create("validator").caPem(), "ehloName", "idp.example.com"), "pw"), false);
    }

    @Test
    void tlsModeNone_onlyWithTheDevProfile() {
        final MessagingProviderWriteDto none = email("SMTP", Map.of("host", "localhost", "tlsMode", "NONE"), null);
        assertThat(errors(() -> prod.validate(none, false))).containsOnlyKeys("config.tlsMode");
        dev.validate(none, false);
    }

    @Test
    void cloudflare_requiresTheAccountIdAndToken_andAnHttpsBaseUrlOutsideDev() {
        assertThat(errors(() -> prod.validate(email("CLOUDFLARE", Map.of(), null), false)))
                .containsKeys("config.accountId", "secret");
        // A token already stored is kept (write-only secret).
        prod.validate(email("CLOUDFLARE", Map.of("accountId", "abc"), null), true);

        final MessagingProviderWriteDto http = email("CLOUDFLARE", Map.of("accountId", "abc",
                "baseUrl", "http://proxy.example.com/client/v4"), "token");
        assertThat(errors(() -> prod.validate(http, false))).containsOnlyKeys("config.baseUrl");
        dev.validate(http, false);
        assertThat(errors(() -> prod.validate(email("CLOUDFLARE", Map.of("accountId", "abc",
                "baseUrl", "https://user:pw@proxy.example.com"), "token"), false))).containsOnlyKeys("config.baseUrl");
        assertThat(errors(() -> prod.validate(email("CLOUDFLARE", Map.of("accountId", "a/b"), "token"), false)))
                .containsOnlyKeys("config.accountId");
    }

    @Test
    void aCredentialInConfig_movesToTheWriteOnlySecret() {
        final Map<String, String> config = new LinkedHashMap<>(Map.of("accountId", "abc", "apiToken", "cf-token-1"));
        final MessagingProviderWriteDto saved = prod.validate(email("CLOUDFLARE", config, null), false);
        assertThat(saved.secret()).isEqualTo("cf-token-1");
        assertThat(saved.config()).doesNotContainKey("apiToken").doesNotContainValue("cf-token-1");

        final MessagingProviderWriteDto smtp = prod.validate(email("SMTP",
                Map.of("host", "smtp.example.com", "password", "pw-1"), null), false);
        assertThat(smtp.secret()).isEqualTo("pw-1");
        assertThat(smtp.config()).doesNotContainKey("password");

        assertThat(errors(() -> prod.validate(email("SMTP", Map.of("host", "smtp.example.com",
                "clientSecret", "x"), null), false))).containsOnlyKeys("config.clientSecret");
    }

    @Test
    void http_requiresAnAbsoluteUrl() {
        assertThat(errors(() -> prod.validate(email("HTTP", Map.of(), null), false))).containsOnlyKeys("config.url");
        assertThat(errors(() -> prod.validate(email("HTTP", Map.of("url", "ftp://relay.example.com"), null), false)))
                .containsOnlyKeys("config.url");
    }

    @Test
    void theFromAddress_mustBeOneAddress() {
        assertThatThrownBy(() -> prod.validate(new MessagingProviderWriteDto("acme", "EMAIL", "SMTP", true,
                "a@example.com, b@example.com", null, Map.of("host", "smtp.example.com"), null), false))
                .isInstanceOf(ProviderValidationException.class);
        assertThat(errors(() -> prod.validate(new MessagingProviderWriteDto("acme", "EMAIL", "SMTP", true,
                "no-reply@example.com", "Acme\r\nBcc: x@example.com", Map.of("host", "smtp.example.com"), null), false)))
                .containsOnlyKeys("fromName");
    }

    @Test
    void theRealmsSendLimit_isAPositiveNumber_forEveryEmailDriver() {
        assertThat(errors(() -> prod.validate(email("LOG", Map.of("sendLimitPerMinute", "0"), null), false)))
                .containsOnlyKeys("config.sendLimitPerMinute");
        assertThat(errors(() -> prod.validate(email("SMTP", Map.of("host", "smtp.example.com",
                "sendLimitPerMinute", "lots"), null), false))).containsOnlyKeys("config.sendLimitPerMinute");
        prod.validate(email("SMTP", Map.of("host", "smtp.example.com", "sendLimitPerMinute", "30"), null), false);
        prod.validate(email("LOG", Map.of("sendLimitPerMinute", "1000000"), null), false);
    }
}
