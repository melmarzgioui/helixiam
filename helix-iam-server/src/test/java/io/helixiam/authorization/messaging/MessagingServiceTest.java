/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging;

import io.helixiam.authorization.amqp.messaging.MessageTemplateDto;
import io.helixiam.authorization.amqp.messaging.MessagingAdminPublisher;
import io.helixiam.authorization.amqp.messaging.ResolveRequest;
import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.authorization.messaging.driver.EmailDriver;
import io.helixiam.authorization.messaging.driver.SmsDriver;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Helix IAM notifications (N3): resolves the realm's enabled provider + template, renders the message, and
 * dispatches via the matching driver. Returns false (so the caller can fall back to the dev log) when the
 * realm has no provider configured.
 */
class MessagingServiceTest {

    private final MessagingAdminPublisher publisher = mock(MessagingAdminPublisher.class);

    private static final class CapturingSms implements SmsDriver {
        String to;
        String message;
        @Override public String driver() { return "HTTP"; }
        @Override public void send(final ResolvedProviderDto p, final String to, final String message) {
            this.to = to; this.message = message;
        }
    }

    @Test
    void sendSms_resolvesProviderAndTemplate_rendersAndDispatches() {
        final CapturingSms driver = new CapturingSms();
        final MessagingService service = new MessagingService(publisher, List.of(driver), List.of(), List.of());
        when(publisher.enabledProviders(any(ResolveRequest.class))).thenReturn(List.of(
                new ResolvedProviderDto("SMS", "HTTP", "+15550100", "Helix",
                        Map.of("url", "https://gw/send"), "tok")));
        when(publisher.listTemplates("master")).thenReturn(List.of(
                new MessageTemplateDto("t1", "master", "otp-sms", "SMS", null, "{{realm}} code {{code}}", true, false)));

        final boolean sent = service.sendSms("master", "+15551234567", "otp-sms",
                Map.of("realm", "master", "code", "987654"));

        assertThat(sent).isTrue();
        assertThat(driver.to).isEqualTo("+15551234567");
        assertThat(driver.message).isEqualTo("master code 987654");
    }

    @Test
    void sendSms_returnsFalse_whenNoProviderConfigured() {
        final MessagingService service = new MessagingService(publisher, List.of(new CapturingSms()), List.of(), List.of());
        when(publisher.enabledProviders(any())).thenReturn(List.of());

        assertThat(service.sendSms("master", "+1", "otp-sms", Map.of())).isFalse();
    }

    @Test
    void sendEmail_rendersSubjectAndBody_andDispatches() {
        final var driver = mock(EmailDriver.class);
        when(driver.driver()).thenReturn("SMTP");
        final MessagingService service = new MessagingService(publisher, List.of(), List.of(driver), List.of());
        when(publisher.enabledProviders(any())).thenReturn(List.of(
                new ResolvedProviderDto("EMAIL", "SMTP", "no-reply@h.test", "Helix",
                        Map.of("host", "smtp"), "pw")));
        when(publisher.listTemplates("master")).thenReturn(List.of(
                new MessageTemplateDto("t", "master", "otp-email", "EMAIL", "Code for {{user}}", "Your code: {{code}}", true, false)));

        final boolean sent = service.sendEmail("master", "ada@h.test", "otp-email",
                Map.of("user", "Ada", "code", "123456"));

        assertThat(sent).isTrue();
        org.mockito.Mockito.verify(driver).send(any(), eq("ada@h.test"), eq("Code for Ada"), eq("Your code: 123456"), eq(false));
    }

    @Test
    void sendEmail_passesHtmlFlag_whenTemplateIsHtml() {
        final var driver = mock(EmailDriver.class);
        when(driver.driver()).thenReturn("SMTP");
        final MessagingService service = new MessagingService(publisher, List.of(), List.of(driver), List.of());
        when(publisher.enabledProviders(any())).thenReturn(List.of(
                new ResolvedProviderDto("EMAIL", "SMTP", "no-reply@h.test", "Helix", Map.of("host", "smtp"), "pw")));
        when(publisher.listTemplates("master")).thenReturn(List.of(
                new MessageTemplateDto("t", "master", "otp-email", "EMAIL", "Hi", "<b>{{code}}</b>", true, true)));

        service.sendEmail("master", "ada@h.test", "otp-email", Map.of("code", "123456"));

        // HTML templates are sent inside the shared branded layout (HelixIAM when no branding source is set).
        org.mockito.Mockito.verify(driver).send(any(), eq("ada@h.test"), eq("Hi"),
                org.mockito.ArgumentMatchers.argThat(b -> b.startsWith("<!DOCTYPE html>") && b.contains("<b>123456</b>")
                        && b.contains(">HelixIAM<")), eq(true));
    }

    @Test
    void htmlEmail_isWrappedInTheBrandedLayout_withEscapedValues() {
        final var driver = mock(EmailDriver.class);
        when(driver.driver()).thenReturn("SMTP");
        final MessagingService service = new MessagingService(publisher, List.of(), List.of(driver), List.of());
        service.setEmailBranding(realm -> new EmailBranding("Harbor & Pine", "https://cdn.example/logo.png", "#B4532A"));
        when(publisher.enabledProviders(any())).thenReturn(List.of(
                new ResolvedProviderDto("EMAIL", "SMTP", "no-reply@h.test", "Helix", Map.of("host", "smtp"), "pw")));
        when(publisher.listTemplates("mf")).thenReturn(List.of(new MessageTemplateDto("t", "mf", "magic-link-email", "EMAIL",
                "Sign in to {{realm}}", "<p>Hi {{user}}</p><p><a href=\"{{link}}\" data-button>Sign in</a></p>", true, true)));

        assertThat(service.sendEmail("mf", "ada@h.test", "magic-link-email",
                Map.of("realm", "mf", "user", "<b>Ada</b>", "link", "https://idp.example/v?t=1"))).isTrue();

        final org.mockito.ArgumentCaptor<String> body = org.mockito.ArgumentCaptor.forClass(String.class);
        org.mockito.Mockito.verify(driver).send(any(), eq("ada@h.test"), eq("Sign in to mf"), body.capture(), eq(true));
        assertThat(body.getValue()).startsWith("<!DOCTYPE html>").contains("https://cdn.example/logo.png")
                .contains("bgcolor=\"#B4532A\"").contains("&lt;b&gt;Ada&lt;/b&gt;").doesNotContain("<b>Ada</b>");
    }
}
