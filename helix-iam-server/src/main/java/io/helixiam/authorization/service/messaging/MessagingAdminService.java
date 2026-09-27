/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.messaging;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.helixiam.authorization.domain.messaging.MessageTemplate;
import io.helixiam.authorization.domain.messaging.MessagingProvider;
import io.helixiam.authorization.domain.messaging.admin.MessageTemplateDto;
import io.helixiam.authorization.domain.messaging.admin.MessagingProviderDto;
import io.helixiam.authorization.domain.messaging.admin.MessagingProviderWriteDto;
import io.helixiam.authorization.messaging.DefaultMessageTemplates;
import io.helixiam.authorization.repository.messaging.MessageTemplateRepository;
import io.helixiam.authorization.repository.messaging.MessagingProviderRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Helix IAM notifications (N1): the per-realm store for messaging providers (SMS/email/push) and message
 * templates. Provider secrets are write-only (kept on update when omitted, never returned). Templates seed a
 * sensible default set per realm the first time they're listed.
 */
@Service
public class MessagingAdminService {

    private final MessagingProviderRepository providers;
    private final MessageTemplateRepository templates;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public MessagingAdminService(final MessagingProviderRepository providers, final MessageTemplateRepository templates) {
        this.providers = providers;
        this.templates = templates;
    }

    public List<MessagingProviderDto> listProviders(final String realmId) {
        return providers.findByRealmId(realmId).stream().map(this::toDto).toList();
    }

    /**
     * SENDER path (N3): the realm's ENABLED providers for a channel, WITH their decrypted secret. SMS/email
     * normally yield one; PUSH yields the enabled FCM+APNs. Server-to-server only — never exposed via REST.
     */
    public List<io.helixiam.authorization.domain.messaging.admin.ResolvedProviderDto> enabledProviders(
            final String realmId, final String channel) {
        return providers.findByRealmIdAndChannel(realmId, channel).stream()
                .filter(p -> Boolean.TRUE.equals(p.getEnabled()))
                .map(p -> new io.helixiam.authorization.domain.messaging.admin.ResolvedProviderDto(
                        p.getChannel(), p.getDriver(), p.getFromAddress(), p.getFromName(),
                        readJson(p.getConfig()), p.getSecret()))
                .toList();
    }

    @Transactional
    public MessagingProviderDto saveProvider(final MessagingProviderWriteDto write) {
        final MessagingProvider entity = providers
                .findByRealmIdAndChannelAndDriver(write.realmId(), write.channel(), write.driver())
                .orElseGet(MessagingProvider::new);
        entity.setRealmId(write.realmId());
        entity.setChannel(write.channel());
        entity.setDriver(write.driver());
        entity.setEnabled(write.enabled());
        entity.setFromAddress(blankToNull(write.fromAddress()));
        entity.setFromName(blankToNull(write.fromName()));
        entity.setConfig(writeJson(write.config()));
        // Write-only secret: replace only when a non-blank value is supplied; otherwise keep what's stored.
        if (write.secret() != null && !write.secret().isBlank()) {
            entity.setSecret(write.secret());
        }
        return toDto(providers.save(entity));
    }

    @Transactional
    public boolean deleteProvider(final String realmId, final String channel, final String driver) {
        return providers.findByRealmIdAndChannelAndDriver(realmId, channel, driver).map(p -> {
            providers.delete(p);
            return true;
        }).orElse(false);
    }

    public List<MessageTemplateDto> listTemplates(final String realmId) {
        final List<MessageTemplate> existing = templates.findByRealmId(realmId);
        if (existing.isEmpty()) {
            final List<MessageTemplate> seeded = defaultTemplates(realmId);
            templates.saveAll(seeded);
            return seeded.stream().map(MessagingAdminService::toDto).toList();
        }
        // C3: a realm seeded before a template key existed (e.g. verify-email) gets the missing defaults too, so a
        // new message never goes out with an empty body. Existing (possibly edited) templates are left alone.
        final java.util.Set<String> keys = new java.util.HashSet<>();
        existing.forEach(t -> keys.add(t.getTemplateKey()));
        final List<MessageTemplate> missing = defaultTemplates(realmId).stream()
                .filter(t -> !keys.contains(t.getTemplateKey())).toList();
        if (!missing.isEmpty()) {
            templates.saveAll(missing);
            final List<MessageTemplate> all = new ArrayList<>(existing);
            all.addAll(missing);
            return all.stream().map(MessagingAdminService::toDto).toList();
        }
        return existing.stream().map(MessagingAdminService::toDto).toList();
    }

    @Transactional
    public MessageTemplateDto saveTemplate(final MessageTemplateDto dto) {
        final MessageTemplate entity = templates.findByRealmIdAndTemplateKey(dto.realmId(), dto.templateKey())
                .orElseGet(MessageTemplate::new);
        entity.setRealmId(dto.realmId());
        entity.setTemplateKey(dto.templateKey());
        entity.setChannel(dto.channel());
        entity.setSubject(blankToNull(dto.subject()));
        entity.setBody(dto.body());
        entity.setEnabled(dto.enabled());
        entity.setHtml(dto.html());
        return toDto(templates.save(entity));
    }

    /** The starter template set every realm gets ({@link DefaultMessageTemplates#english()}), editable afterwards. */
    private List<MessageTemplate> defaultTemplates(final String realmId) {
        final List<MessageTemplate> list = new ArrayList<>();
        for (final DefaultMessageTemplates.Template t : DefaultMessageTemplates.english()) {
            list.add(template(realmId, t.key(), t.channel(), t.subject(), t.body(), t.html()));
        }
        return list;
    }

    /** B1: the confirmation link sent to a changed email address ({@code {{link}}}, {@code {{ttl}}}). */
    public static final String EMAIL_CHANGE_VERIFY = DefaultMessageTemplates.EMAIL_CHANGE_VERIFY;
    /** B1: the notice sent to the previous address when the email address changes. */
    public static final String EMAIL_CHANGED_NOTICE = DefaultMessageTemplates.EMAIL_CHANGED_NOTICE;

    /**
     * B1: makes sure the realm has the default template {@code key} (a realm whose templates were seeded before the
     * template existed gets it now), without touching the realm's other templates.
     */
    @Transactional
    public void ensureDefaultTemplate(final String realmId, final String key) {
        if (templates.findByRealmIdAndTemplateKey(realmId, key).isPresent()) {
            return;
        }
        if (templates.findByRealmId(realmId).isEmpty()) {
            listTemplates(realmId); // first read seeds the whole default set
            return;
        }
        defaultTemplates(realmId).stream().filter(t -> key.equals(t.getTemplateKey())).findFirst()
                .ifPresent(templates::save);
    }

    private static MessageTemplate template(final String realmId, final String key, final String channel,
                                            final String subject, final String body, final boolean html) {
        final MessageTemplate t = new MessageTemplate();
        t.setRealmId(realmId);
        t.setTemplateKey(key);
        t.setChannel(channel);
        t.setSubject(subject);
        t.setBody(body);
        t.setEnabled(true);
        t.setHtml(html);
        return t;
    }

    private MessagingProviderDto toDto(final MessagingProvider p) {
        return new MessagingProviderDto(p.getId(), p.getRealmId(), p.getChannel(), p.getDriver(),
                Boolean.TRUE.equals(p.getEnabled()), p.getFromAddress(), p.getFromName(), readJson(p.getConfig()),
                p.getSecret() != null && !p.getSecret().isBlank());
    }

    private static MessageTemplateDto toDto(final MessageTemplate t) {
        return new MessageTemplateDto(t.getId(), t.getRealmId(), t.getTemplateKey(), t.getChannel(),
                t.getSubject(), t.getBody(), Boolean.TRUE.equals(t.getEnabled()), Boolean.TRUE.equals(t.getHtml()));
    }

    private static String blankToNull(final String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private String writeJson(final Map<String, String> config) {
        if (config == null || config.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(config);
        } catch (final Exception e) {
            throw new IllegalArgumentException("Invalid provider config: " + e.getMessage(), e);
        }
    }

    private Map<String, String> readJson(final String json) {
        if (json == null || json.isBlank()) {
            return new LinkedHashMap<>();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<LinkedHashMap<String, String>>() { });
        } catch (final Exception e) {
            return new LinkedHashMap<>();
        }
    }
}
