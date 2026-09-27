/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.notification.delivery.SmtpProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/** The server-wide email default, from properties and mounted secret files (re-read at every send). */
class GlobalEmailProviderTest {

    @TempDir
    Path dir;

    @Test
    void smtpIsTheDefault_andEmptyWithoutAHost() {
        assertThat(new GlobalEmailProvider(new EmailProperties(), new SmtpProperties(), null).resolve()).isEmpty();

        final SmtpProperties smtp = new SmtpProperties();
        smtp.setHost("smtp.example.com");
        smtp.setTlsMode("IMPLICIT");
        smtp.setUsername("mailer");
        smtp.setPassword("pw");
        smtp.setConnectTimeout(Duration.ofSeconds(3));
        final ResolvedProviderDto p = new GlobalEmailProvider(new EmailProperties(), smtp, null).resolve().orElseThrow();
        assertThat(p.driver()).isEqualTo("SMTP");
        assertThat(p.config()).containsEntry("host", "smtp.example.com").containsEntry("tlsMode", "IMPLICIT")
                .containsEntry("connectTimeoutMs", "3000").doesNotContainKey("port");
        assertThat(p.secret()).isEqualTo("pw");
        assertThat(p.fromAddress()).isEqualTo("no-reply@helix.local");
    }

    @Test
    void theSmtpPasswordFile_winsAndIsReadAtEveryCall() throws Exception {
        final Path file = dir.resolve("smtp-password");
        Files.writeString(file, "first\n");
        final SmtpProperties smtp = new SmtpProperties();
        smtp.setHost("smtp.example.com");
        smtp.setPassword("inline");
        smtp.setPasswordFile(file.toString());
        final GlobalEmailProvider global = new GlobalEmailProvider(null, smtp, null);

        assertThat(global.resolve().orElseThrow().secret()).isEqualTo("first");
        Files.writeString(file, "rotated");
        assertThat(global.resolve().orElseThrow().secret()).isEqualTo("rotated");
    }

    @Test
    void cloudflare_fromPropertiesAndATokenFile() throws Exception {
        final Path token = dir.resolve("cf-token");
        Files.writeString(token, "cf-token-1\n");
        final EmailProperties email = new EmailProperties();
        email.setDriver("cloudflare");
        email.setFromAddress("no-reply@example.com");
        email.setFromName("Example");
        final CloudflareProperties cf = new CloudflareProperties();
        cf.setAccountId("abc123");
        cf.setApiTokenFile(token.toString());
        final GlobalEmailProvider global = new GlobalEmailProvider(email, new SmtpProperties(), cf);

        final ResolvedProviderDto p = global.resolve().orElseThrow();
        assertThat(p.driver()).isEqualTo("CLOUDFLARE");
        assertThat(p.config()).containsEntry("accountId", "abc123").doesNotContainKey("baseUrl");
        assertThat(p.secret()).isEqualTo("cf-token-1");
        assertThat(p.fromAddress()).isEqualTo("no-reply@example.com");
        assertThat(p.fromName()).isEqualTo("Example");
        assertThat(cf.toString()).doesNotContain("cf-token-1");

        Files.writeString(token, "cf-token-2");
        assertThat(global.resolve().orElseThrow().secret()).isEqualTo("cf-token-2");
    }

    @Test
    void cloudflare_withoutAToken_isNotConfigured() {
        final EmailProperties email = new EmailProperties();
        email.setDriver("cloudflare");
        final CloudflareProperties cf = new CloudflareProperties();
        cf.setAccountId("abc123");
        cf.setApiTokenFile(dir.resolve("missing").toString());

        assertThat(new GlobalEmailProvider(email, null, cf).resolve()).isEmpty();
    }

    @Test
    void logAndUnknownDrivers() {
        final EmailProperties email = new EmailProperties();
        email.setDriver("LOG");
        assertThat(new GlobalEmailProvider(email, null, null).resolve().orElseThrow().driver()).isEqualTo("LOG");
        email.setDriver("pigeon");
        assertThat(new GlobalEmailProvider(email, null, null).resolve()).isEmpty();
    }
}
