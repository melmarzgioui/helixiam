/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.fasterxml.jackson.databind.JsonNode;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.service.emailverification.EmailVerificationMessage;
import io.helixiam.authorization.service.emailverification.RealmEmailVerificationSender;
import io.helixiam.authorization.service.magiclink.MagicLinkMessage;
import io.helixiam.authorization.service.magiclink.RealmMagicLinkSender;
import io.helixiam.e2e.E2eAdminSession;
import io.helixiam.e2e.E2eHttp;
import io.helixiam.e2e.E2eSeed;
import io.helixiam.testsupport.CloudflareApiMock;
import io.helixiam.testsupport.TestSmtpServer;
import io.helixiam.testsupport.TestTls;
import jakarta.mail.BodyPart;
import jakarta.mail.internet.MimeMultipart;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pluggable email delivery, end to end on the real server: a realm configured with the Cloudflare Email Service
 * driver (over HTTPS, to a local mock) and a realm configured with SMTP over implicit TLS (to a local TLS-only SMTP
 * server) each deliver the verification email, the password-reset email (from a real browser) and the magic link,
 * and every one of them has a plain-text part that carries its link.
 */
class EmailDriversBrowserE2eTest extends AbstractBrowserE2eTest {

    static final String CF_TOKEN = "cf-e2e-token-58d1c0";
    static final String SMTP_PASSWORD = "smtp-e2e-password-3b9e";
    private static final Duration MAIL_WAIT = Duration.ofSeconds(15);

    private static TestTls tls;
    private static CloudflareApiMock cloudflare;
    private static TestSmtpServer smtps;

    @BeforeAll
    static void startMailServers() {
        tls = TestTls.create("email-e2e");
        cloudflare = CloudflareApiMock.https(tls);
        HarnessEgressGuard.allow(cloudflare.port());
        smtps = TestSmtpServer.implicitTls(tls);
    }

    @AfterAll
    static void stopMailServers() {
        HarnessEgressGuard.revoke(cloudflare.port());
        cloudflare.close();
        smtps.close();
    }

    /** The CLOUDFLARE provider for the mock. */
    static Map<String, Object> cloudflareProvider(final CloudflareApiMock mock, final TestTls tls) {
        final Map<String, Object> provider = new LinkedHashMap<>();
        provider.put("channel", "EMAIL");
        provider.put("driver", "CLOUDFLARE");
        provider.put("enabled", true);
        provider.put("fromAddress", "no-reply@acme.example.com");
        provider.put("fromName", "Acme");
        provider.put("config", Map.of("accountId", "acme0123456789", "baseUrl", mock.baseUrl(), "caBundle", tls.caPem()));
        provider.put("secret", CF_TOKEN);
        return provider;
    }

    /** The SMTP (implicit TLS) provider for the local SMTPS server. */
    static Map<String, Object> smtpsProvider(final TestSmtpServer server, final TestTls tls) {
        final Map<String, Object> provider = new LinkedHashMap<>();
        provider.put("channel", "EMAIL");
        provider.put("driver", "SMTP");
        provider.put("enabled", true);
        provider.put("fromAddress", "no-reply@acme.example.com");
        provider.put("fromName", "Acme");
        provider.put("config", Map.of("host", "localhost", "port", String.valueOf(server.port()), "tlsMode", "IMPLICIT",
                "username", "mailer", "caBundle", tls.caPem()));
        provider.put("secret", SMTP_PASSWORD);
        return provider;
    }

    /** A fresh realm whose only email provider is {@code provider}. */
    private String realmWith(final Map<String, Object> provider) {
        final String realm = E2eSeed.unique("acme-mail");
        seed().realm(realm, "Acme");
        final E2eAdminSession admin = adminSession();
        final E2eHttp.Response saved = admin.put("/admin/realms/" + realm + "/messaging/providers", provider);
        assertThat(saved.status()).as(saved.toString()).isEqualTo(200);
        return realm;
    }

    @Test
    void cloudflare_deliversVerificationResetAndMagicLink_withTheLinkInTheTextPart() {
        final String realm = realmWith(cloudflareProvider(cloudflare, tls));

        final Function<String, CloudflareApiMock.Request> sentWith = marker -> cloudflare.await(
                r -> r.body().contains(marker), MAIL_WAIT);
        final Sent sent = sendAll(realm, marker -> {
            final JsonNode json = sentWith.apply(marker).json();
            return new Mail(json.path("to").path(0).path("address").asText(), json.path("subject").asText(),
                    json.path("html").asText(), json.path("text").asText());
        });

        final CloudflareApiMock.Request request = sentWith.apply(sent.verifyLink());
        assertThat(request.path()).isEqualTo("/client/v4/accounts/acme0123456789/email/sending/send");
        assertThat(request.authorization()).isEqualTo("Bearer " + CF_TOKEN);
        assertThat(request.json().path("from").path("address").asText()).isEqualTo("no-reply@acme.example.com");
        assertThat(request.json().path("from").path("name").asText()).isEqualTo("Acme");
    }

    @Test
    void smtpImplicitTls_deliversVerificationResetAndMagicLink_withTheLinkInTheTextPart() {
        final String realm = realmWith(smtpsProvider(smtps, tls));

        sendAll(realm, marker -> {
            final TestSmtpServer.Received received = smtps.await(r -> r.raw().contains(marker)
                    || decoded(r).contains(marker), MAIL_WAIT);
            assertThat(received.tls()).isTrue();
            assertThat(received.authUser()).isEqualTo("mailer");
            assertThat(received.authPassword()).isEqualTo(SMTP_PASSWORD);
            try {
                final jakarta.mail.internet.MimeMessage mime = received.mime();
                final MimeMultipart parts = (MimeMultipart) mime.getContent();
                final BodyPart text = parts.getBodyPart(0);
                final BodyPart html = parts.getBodyPart(1);
                assertThat(text.getContentType()).contains("text/plain");
                assertThat(html.getContentType()).contains("text/html");
                return new Mail(mime.getAllRecipients()[0].toString(), mime.getSubject(), (String) html.getContent(),
                        (String) text.getContent());
            } catch (final Exception e) {
                throw new AssertionError(e);
            }
        });
    }

    private record Mail(String to, String subject, String html, String text) {
    }

    private record Sent(String verifyLink, String magicLink, String resetLink) {
    }

    /**
     * Sends the verification email and the magic link through the server's senders and the reset email from a
     * browser, then reads each with {@code read} (given a string only that email contains) and checks the link is in
     * both parts.
     */
    private Sent sendAll(final String realm, final Function<String, Mail> read) {
        // The reset page (an email field) is given the account's address; the link goes to that stored address.
        final E2eSeed.SeededUser ada = seed().user(realm, E2eSeed.unique("ada"), "Email-Drivers-Passw0rd-2026!");
        final String inbox = E2eSeed.unique("inbox") + "@example.com";
        final String realmUrl = baseUrl() + "/realms/" + realm;
        final String verifyLink = realmUrl + "/verify-email?token=" + E2eSeed.unique("v3r1fy");
        final String magicLink = realmUrl + "/login/magic/verify?token=" + E2eSeed.unique("m4g1c");

        RealmContextHolder.set(realm);
        try {
            assertThat(context.getBean(RealmEmailVerificationSender.class).send(new EmailVerificationMessage(realm,
                    ada.userId(), inbox, verifyLink, 24))).isTrue();
            context.getBean(RealmMagicLinkSender.class).send(new MagicLinkMessage(realm, ada.userId(), inbox, magicLink,
                    15));
        } finally {
            RealmContextHolder.clear();
        }

        final Mail verify = read.apply(verifyLink);
        assertThat(verify.to()).isEqualTo(inbox);
        assertLinkInBothParts(verify, verifyLink);

        final Mail magic = read.apply(magicLink);
        assertThat(magic.to()).isEqualTo(inbox);
        assertLinkInBothParts(magic, magicLink);

        page().navigate(realmUrl + "/reset/password?lang=en");
        page().locator("#username").fill(ada.username() + "@e2e.helixiam.test");
        submit(page().locator("#passwordReset button[type=submit]"));
        final String resetPrefix = realmUrl + "/reset/password/";
        final Mail reset = read.apply(resetPrefix);
        assertThat(reset.to()).isEqualTo(ada.username() + "@e2e.helixiam.test"); // the stored address, not the typed one
        final java.util.regex.Matcher m = java.util.regex.Pattern.compile(java.util.regex.Pattern.quote(resetPrefix)
                + "[A-Za-z0-9_-]+").matcher(reset.text());
        assertThat(m.find()).as("a reset link in the text part: " + reset.text()).isTrue();
        final String resetLink = m.group();
        assertLinkInBothParts(reset, resetLink);
        return new Sent(verifyLink, magicLink, resetLink);
    }

    private static void assertLinkInBothParts(final Mail mail, final String link) {
        assertThat(mail.text()).as(mail.subject() + ": text part").contains(link).doesNotContain("<a ");
        assertThat(mail.html().replace("&amp;", "&")).as(mail.subject() + ": html part").contains(link);
    }

    /** The message with quoted-printable soft breaks undone, to find a marker in the raw MIME. */
    private static String decoded(final TestSmtpServer.Received r) {
        return r.raw().replace("=\r\n", "").replace("=3D", "=");
    }
}
