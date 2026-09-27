/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.messaging;

import io.helixiam.authorization.domain.messaging.MessageTemplate;
import io.helixiam.authorization.domain.messaging.MessagingProvider;
import io.helixiam.authorization.domain.messaging.admin.MessageTemplateDto;
import io.helixiam.authorization.domain.messaging.admin.MessagingProviderDto;
import io.helixiam.authorization.domain.messaging.admin.MessagingProviderWriteDto;
import io.helixiam.authorization.repository.messaging.MessageTemplateRepository;
import io.helixiam.authorization.repository.messaging.MessagingProviderRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM notifications (N1): per-realm provider + template store. Secrets are write-only (kept on update
 * when omitted, never echoed back); templates seed a default set per realm on first read.
 */
class MessagingAdminServiceTest {

    private MessagingProviderRepository providers;
    private MessageTemplateRepository templates;
    private MessagingAdminService service;

    @BeforeEach
    void setUp() {
        providers = mock(MessagingProviderRepository.class);
        templates = mock(MessageTemplateRepository.class);
        when(providers.save(any())).thenAnswer(i -> i.getArgument(0));
        when(templates.save(any())).thenAnswer(i -> i.getArgument(0));
        service = new MessagingAdminService(providers, templates);
    }

    @Test
    void saveProvider_storesSecret_andNeverEchoesItBack() {
        when(providers.findByRealmIdAndChannelAndDriver("master", "SMS", "TWILIO")).thenReturn(Optional.empty());

        final MessagingProviderDto dto = service.saveProvider(new MessagingProviderWriteDto(
                "master", "SMS", "TWILIO", true, "+15550100", "Helix",
                Map.of("accountSid", "AC123"), "the-auth-token"));

        final ArgumentCaptor<MessagingProvider> captor = ArgumentCaptor.forClass(MessagingProvider.class);
        verify(providers).save(captor.capture());
        assertThat(captor.getValue().getSecret()).isEqualTo("the-auth-token");
        assertThat(captor.getValue().getConfig()).contains("AC123");
        // The returned DTO masks the secret — only reports that one is set.
        assertThat(dto.secretSet()).isTrue();
        assertThat(dto.config()).containsEntry("accountSid", "AC123");
        assertThat(dto.driver()).isEqualTo("TWILIO");
    }

    @Test
    void saveProvider_keepsExistingSecret_whenWriteOmitsIt() {
        final MessagingProvider existing = new MessagingProvider();
        existing.setId("p1");
        existing.setRealmId("master");
        existing.setChannel("EMAIL");
        existing.setDriver("SMTP");
        existing.setSecret("stored-password");
        when(providers.findByRealmIdAndChannelAndDriver("master", "EMAIL", "SMTP")).thenReturn(Optional.of(existing));

        service.saveProvider(new MessagingProviderWriteDto("master", "EMAIL", "SMTP", true,
                "no-reply@helix.test", "Helix", Map.of("host", "smtp.test", "port", "587"), null));

        final ArgumentCaptor<MessagingProvider> captor = ArgumentCaptor.forClass(MessagingProvider.class);
        verify(providers).save(captor.capture());
        assertThat(captor.getValue().getSecret()).isEqualTo("stored-password"); // unchanged
        assertThat(captor.getValue().getFromAddress()).isEqualTo("no-reply@helix.test");
    }

    @Test
    void listTemplates_seedsDefaultsOnFirstRead() {
        when(templates.findByRealmId("master")).thenReturn(List.of());

        final List<MessageTemplateDto> seeded = service.listTemplates("master");

        verify(templates).saveAll(anyList());
        assertThat(seeded).extracting(MessageTemplateDto::templateKey)
                .contains("otp-sms", "otp-email", "magic-link-email", "push-approval");
        assertThat(seeded).allSatisfy(t -> assertThat(t.body()).isNotBlank());
    }

    @Test
    void listTemplates_keepsExistingTemplates_andOnlyAddsMissingDefaults() {
        final MessageTemplate t = new MessageTemplate();
        t.setRealmId("master"); t.setTemplateKey("otp-sms"); t.setChannel("SMS"); t.setBody("x");
        when(templates.findByRealmId("master")).thenReturn(List.of(t));

        final List<MessageTemplateDto> listed = service.listTemplates("master");

        // C3: a realm seeded before a key existed (verify-email) gets the missing defaults; the edited one stays.
        @SuppressWarnings("unchecked")
        final org.mockito.ArgumentCaptor<List<MessageTemplate>> added = org.mockito.ArgumentCaptor.forClass(List.class);
        verify(templates).saveAll(added.capture());
        assertThat(added.getValue()).extracting(MessageTemplate::getTemplateKey)
                .doesNotContain("otp-sms").contains("verify-email", "magic-link-email");
        assertThat(listed).filteredOn(d -> "otp-sms".equals(d.templateKey())).singleElement()
                .satisfies(d -> assertThat(d.body()).isEqualTo("x"));
    }

    @Test
    void listTemplates_doesNotReseed_whenEveryDefaultIsPresent() {
        when(templates.findByRealmId("master")).thenReturn(List.of());
        final List<MessageTemplateDto> seeded = service.listTemplates("master");
        final List<MessageTemplate> all = seeded.stream().map(d -> {
            final MessageTemplate m = new MessageTemplate();
            m.setRealmId("master"); m.setTemplateKey(d.templateKey()); m.setChannel(d.channel()); m.setBody(d.body());
            return m;
        }).toList();
        org.mockito.Mockito.reset(templates);
        when(templates.findByRealmId("master")).thenReturn(all);

        service.listTemplates("master");

        verify(templates, never()).saveAll(anyList());
    }

    @Test
    void saveTemplate_upsertsByRealmAndKey() {
        when(templates.findByRealmIdAndTemplateKey("master", "otp-email")).thenReturn(Optional.empty());

        service.saveTemplate(new MessageTemplateDto(null, "master", "otp-email", "EMAIL",
                "Your code", "Code: {{code}}", true, true));

        final ArgumentCaptor<MessageTemplate> captor = ArgumentCaptor.forClass(MessageTemplate.class);
        verify(templates).save(captor.capture());
        assertThat(captor.getValue().getSubject()).isEqualTo("Your code");
        assertThat(captor.getValue().getBody()).isEqualTo("Code: {{code}}");
        assertThat(captor.getValue().getHtml()).isTrue();
    }
}
