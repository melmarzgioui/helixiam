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
import io.helixiam.authorization.messaging.driver.PushDriver;
import io.helixiam.authorization.messaging.driver.SmsDriver;
import io.helixiam.authorization.messaging.email.DeliveryResult;
import io.helixiam.authorization.messaging.email.EmailDelivery;
import io.helixiam.authorization.messaging.email.EmailDeliveryException;
import io.helixiam.authorization.messaging.email.EmailMessage;
import io.helixiam.authorization.messaging.email.EmailOutbox;
import io.helixiam.authorization.messaging.email.EmailSendOutcome;
import io.helixiam.authorization.messaging.email.EmailTransport;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Helix IAM notifications (N3): the send path. Resolves the realm's enabled provider for a channel + the
 * named template, renders the message, and dispatches via the matching driver. Returns {@code false} (so the
 * caller can fall back to the dev log) when the realm has no provider configured, or no driver matches. Email goes
 * through {@link EmailDelivery} (the email transport SPI), which classifies the outcome.
 */
@Service
public class MessagingService {

    private static final Logger LOG = LogManager.getLogger(MessagingService.class);

    private final MessagingAdminPublisher publisher;
    private final List<SmsDriver> smsDrivers;
    private final List<PushDriver> pushDrivers;
    private EmailOutbox outbox;
    private EmailBrandingSource emailBranding;

    @Autowired
    public MessagingService(final MessagingAdminPublisher publisher, final List<SmsDriver> smsDrivers,
                            final EmailDelivery emailDelivery, final List<PushDriver> pushDrivers) {
        this.publisher = publisher;
        this.smsDrivers = smsDrivers;
        this.pushDrivers = pushDrivers;
        this.outbox = EmailOutbox.direct(emailDelivery);
    }

    /** Email through {@code emailTransports} for the realm's own providers only (no global default; tests). */
    public MessagingService(final MessagingAdminPublisher publisher, final List<SmsDriver> smsDrivers,
                            final List<? extends EmailTransport> emailTransports, final List<PushDriver> pushDrivers) {
        this(publisher, smsDrivers, new EmailDelivery(realm -> publisher.enabledProviders(new ResolveRequest(realm, "EMAIL")),
                emailTransports, null, null, null), pushDrivers);
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
            LOG.warn("No SMS driver for '{}' in realm {}",
                    LogSafe.sanitize(provider.driver()), LogSafe.sanitize(realm));
            return false;
        }
        final String body = render(realm, templateKey, vars).body();
        driver.send(provider, to, body);
        return true;
    }

    /**
     * Render {@code templateKey} and email it to {@code to}; false if the realm has no email provider. The email carries
     * no expiring code or link (see {@link #sendEmail(String, String, String, Map, Duration)}).
     *
     * @throws EmailDeliveryException when the provider did not take the email and it is not queued for a retry (the
     *                                classified result is attached)
     */
    public boolean sendEmail(final String realm, final String to, final String templateKey, final Map<String, String> vars) {
        return sendEmail(realm, to, templateKey, vars, null);
    }

    /**
     * Render {@code templateKey} and email it to {@code to} through the realm's email provider, via the
     * {@link EmailOutbox}: the send rate caps, one synchronous attempt, then retries of a transient failure (never
     * after the code or link in the email stops working, {@code validFor} from now; null: it carries none).
     *
     * @return true when the provider took the email or it is queued for a retry; false when the realm has no enabled
     *         email provider with a known driver
     * @throws EmailDeliveryException when the email failed (permanently, or transiently without a retry: rate capped,
     *                                or the code would expire first); the classified result is attached
     */
    public boolean sendEmail(final String realm, final String to, final String templateKey,
                             final Map<String, String> vars, final Duration validFor) {
        if (outbox.realmProvider(realm).isEmpty()) {
            return false;
        }
        final Rendered r = render(realm, templateKey, vars);
        final EmailMessage message = EmailMessage.of(null, to, r.subject(), r.body(), r.html(), r.text())
                .withExpiresAt(validFor == null ? null : Instant.now().plus(validFor));
        final EmailSendOutcome outcome = outbox.send(realm, message, EmailOutbox.SendOptions.TRANSACTIONAL);
        if (!outcome.inFlight()) {
            throw new EmailDeliveryException(outcome.result());
        }
        return true;
    }

    /**
     * Render {@code templateKey} and email it to {@code to} through the realm's email provider, once (the admin test
     * endpoint): the classified result of that attempt, never queued for a retry; empty when the realm has no enabled
     * email provider with a known driver. The send rate caps apply.
     */
    public Optional<DeliveryResult> sendEmailWithResult(final String realm, final String to, final String templateKey,
                                                        final Map<String, String> vars) {
        if (outbox.realmProvider(realm).isEmpty()) {
            return Optional.empty();
        }
        final Rendered r = render(realm, templateKey, vars);
        final EmailMessage message = EmailMessage.of(null, to, r.subject(), r.body(), r.html(), r.text());
        return Optional.of(outbox.send(realm, message, EmailOutbox.SendOptions.TEST).result());
    }

    /** The outbox email goes through (rate caps, retries, bounces); without one, a single synchronous attempt. */
    @Autowired(required = false)
    public void setEmailOutbox(final EmailOutbox outbox) {
        if (outbox != null) {
            this.outbox = outbox;
        }
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
            LOG.warn("Could not resolve PUSH providers for realm {}: {}",
                    LogSafe.sanitize(realm), LogSafe.sanitize(e.getMessage()));
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
            LOG.warn("Could not resolve {} provider for realm {}: {}",
                    LogSafe.sanitize(channel), LogSafe.sanitize(realm), LogSafe.sanitize(e.getMessage()));
            return null;
        }
    }

    /**
     * The message of {@code templateKey} in the user's language: an unedited default template is sent in Dutch to a
     * Dutch user ({@link DefaultMessageTemplates#localise}). An HTML template is rendered with escaped values inside
     * the branded layout, with a plain-text part derived from it (every link and code kept, item 3).
     */
    private Rendered render(final String realm, final String templateKey, final Map<String, String> vars) {
        final EmailBranding branding = emailBranding == null ? EmailBranding.helixIam() : emailBranding.brandingFor(realm);
        final Map<String, String> v = withRealmName(realm, vars, branding);
        final java.util.Locale locale = org.springframework.context.i18n.LocaleContextHolder.getLocale();
        final MessageTemplateDto stored = template(realm, templateKey);
        final DefaultMessageTemplates.Template template = stored == null ? null
                : DefaultMessageTemplates.localise(templateKey, stored.subject(), stored.body(), stored.html(), locale);
        final String subject = template == null ? "" : TemplateRenderer.render(template.subject(), v);
        if (template != null && template.html()) {
            // HTML email: escaped values, inside the shared branded layout (organization in context, else realm).
            final String bodyHtml = TemplateRenderer.renderHtml(template.body(), v);
            return new Rendered(subject, EmailLayout.wrap(branding, subject, bodyHtml, locale), true,
                    EmailLayout.text(branding, EmailText.fromHtml(bodyHtml), locale));
        }
        final String body = template == null ? v.getOrDefault("code", "") : TemplateRenderer.render(template.body(), v);
        return new Rendered(subject, body, false, body);
    }

    /**
     * Item 4: {@code {{realm}}} is the name users know: the organization in context, else the realm's display name,
     * else the realm id. A caller that passes the realm id gets the name; a value a caller chose itself is kept. The id
     * stays available as {@code {{realmId}}}.
     */
    private Map<String, String> withRealmName(final String realm, final Map<String, String> vars,
                                              final EmailBranding branding) {
        final Map<String, String> v = new java.util.LinkedHashMap<>(vars == null ? Map.of() : vars);
        if (realm != null) {
            v.putIfAbsent("realmId", realm);
            final String given = v.get("realm");
            if (emailBranding != null && (given == null || given.equals(realm))) {
                v.put("realm", branding.nameOr(realm));
            }
        }
        return v;
    }

    /** The brand HTML emails are sent under; without one, HelixIAM's. */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setEmailBranding(final EmailBrandingSource emailBranding) {
        this.emailBranding = emailBranding;
    }

    private MessageTemplateDto template(final String realm, final String key) {
        final List<MessageTemplateDto> templates = publisher.listTemplates(realm);
        return templates == null ? null
                : templates.stream().filter(t -> key.equals(t.templateKey()) && t.enabled()).findFirst().orElse(null);
    }

    private record Rendered(String subject, String body, boolean html, String text) {
    }
}
