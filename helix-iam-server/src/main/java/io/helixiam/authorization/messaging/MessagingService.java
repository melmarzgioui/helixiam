/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging;

import io.helixiam.authorization.amqp.messaging.DevicePushTokenDto;
import io.helixiam.authorization.amqp.messaging.MessageTemplateDto;
import io.helixiam.authorization.amqp.messaging.MessagingAdminPublisher;
import io.helixiam.authorization.amqp.messaging.ResolveRequest;
import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.authorization.messaging.driver.EmailDriver;
import io.helixiam.authorization.messaging.driver.PushDriver;
import io.helixiam.authorization.messaging.driver.SmsDriver;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * Helix IAM notifications (N3): the send path. Resolves the realm's enabled provider for a channel + the
 * named template, renders the message, and dispatches via the matching driver. Returns {@code false} (so the
 * caller can fall back to the dev log) when the realm has no provider configured, or no driver matches.
 */
@Service
public class MessagingService {

    private static final Logger LOG = LogManager.getLogger(MessagingService.class);

    private final MessagingAdminPublisher publisher;
    private final List<SmsDriver> smsDrivers;
    private final List<EmailDriver> emailDrivers;
    private final List<PushDriver> pushDrivers;

    public MessagingService(final MessagingAdminPublisher publisher, final List<SmsDriver> smsDrivers,
                            final List<EmailDriver> emailDrivers, final List<PushDriver> pushDrivers) {
        this.publisher = publisher;
        this.smsDrivers = smsDrivers;
        this.emailDrivers = emailDrivers;
        this.pushDrivers = pushDrivers;
    }

    /** Render {@code templateKey} and SMS it to {@code to}; false if the realm has no SMS provider. */
    public boolean sendSms(final String realm, final String to, final String templateKey, final Map<String, String> vars) {
        final ResolvedProviderDto provider = firstEnabled(realm, "SMS");
        if (provider == null) {
            return false;
        }
        final SmsDriver driver = smsDrivers.stream().filter(d -> d.driver().equalsIgnoreCase(provider.driver()))
                .findFirst().orElse(null);
        if (driver == null) {
            LOG.warn("No SMS driver for '{}' in realm {}", provider.driver(), realm);
            return false;
        }
        final String body = render(realm, templateKey, vars).body();
        driver.send(provider, to, body);
        return true;
    }

    /** Render {@code templateKey} and email it to {@code to}; false if the realm has no email provider. */
    public boolean sendEmail(final String realm, final String to, final String templateKey, final Map<String, String> vars) {
        final ResolvedProviderDto provider = firstEnabled(realm, "EMAIL");
        if (provider == null) {
            return false;
        }
        final EmailDriver driver = emailDrivers.stream().filter(d -> d.driver().equalsIgnoreCase(provider.driver()))
                .findFirst().orElse(null);
        if (driver == null) {
            LOG.warn("No email driver for '{}' in realm {}", provider.driver(), realm);
            return false;
        }
        final Rendered r = render(realm, templateKey, vars);
        driver.send(provider, to, r.subject(), r.body(), r.html());
        return true;
    }

    /**
     * Render the realm's {@code templateKey} (push-approval) and deliver it to the user's device tokens via the
     * realm's enabled PUSH providers. Each token is routed to the provider matching its {@code platform}
     * ({@code FCM} / {@code APNS}), so a realm with both reaches Android and iOS devices. {@code data} is the
     * structured payload the app acts on. Returns false when nothing could be delivered.
     */
    public boolean sendPush(final String realm, final List<DevicePushTokenDto> deviceTokens, final String templateKey,
                            final Map<String, String> vars, final Map<String, String> data) {
        if (deviceTokens == null || deviceTokens.isEmpty()) {
            return false;
        }
        final List<ResolvedProviderDto> providers;
        try {
            providers = publisher.enabledProviders(new ResolveRequest(realm, "PUSH"));
        } catch (final RuntimeException e) {
            LOG.warn("Could not resolve PUSH providers for realm {}: {}", realm, e.getMessage());
            return false;
        }
        if (providers == null || providers.isEmpty()) {
            return false;
        }
        final Rendered r = render(realm, templateKey, vars);
        boolean delivered = false;
        for (final ResolvedProviderDto provider : providers) {
            final PushDriver driver = pushDrivers.stream().filter(d -> d.driver().equalsIgnoreCase(provider.driver()))
                    .findFirst().orElse(null);
            if (driver == null) {
                continue;
            }
            final List<String> tokens = deviceTokens.stream()
                    .filter(t -> provider.driver().equalsIgnoreCase(t.platform()))
                    .map(DevicePushTokenDto::token).toList();
            if (!tokens.isEmpty()) {
                driver.send(provider, tokens, r.subject(), r.body(), data);
                delivered = true;
            }
        }
        return delivered;
    }

    private ResolvedProviderDto firstEnabled(final String realm, final String channel) {
        try {
            final List<ResolvedProviderDto> enabled = publisher.enabledProviders(new ResolveRequest(realm, channel));
            return enabled == null || enabled.isEmpty() ? null : enabled.get(0);
        } catch (final RuntimeException e) {
            LOG.warn("Could not resolve {} provider for realm {}: {}", channel, realm, e.getMessage());
            return null;
        }
    }

    private Rendered render(final String realm, final String templateKey, final Map<String, String> vars) {
        final Map<String, String> v = vars == null ? Map.of() : vars;
        final MessageTemplateDto template = template(realm, templateKey);
        final String subject = template == null ? "" : TemplateRenderer.render(template.subject(), v);
        final String body = template == null ? v.getOrDefault("code", "") : TemplateRenderer.render(template.body(), v);
        return new Rendered(subject, body, template != null && template.html());
    }

    private MessageTemplateDto template(final String realm, final String key) {
        final List<MessageTemplateDto> templates = publisher.listTemplates(realm);
        return templates == null ? null
                : templates.stream().filter(t -> key.equals(t.templateKey()) && t.enabled()).findFirst().orElse(null);
    }

    private record Rendered(String subject, String body, boolean html) {
    }
}
