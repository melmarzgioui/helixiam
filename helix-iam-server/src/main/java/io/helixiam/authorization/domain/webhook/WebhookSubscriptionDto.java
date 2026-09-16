package io.helixiam.authorization.domain.webhook;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM B6: subscriber-side two-copy DTO for a webhook subscription (mirrors the publisher's
 * {@code amqp.webhook.WebhookSubscriptionDto}). Carries the {@code secret} over the internal AMQP seam
 * so the publisher's dispatcher can sign payloads; the console-facing controller strips it on read.
 * {@code secretSet} tells the console whether a secret exists without revealing it.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record WebhookSubscriptionDto(String id, String realmId, String name, String url, String secret,
                                     boolean secretSet, String eventTypes, boolean enabled, Long createdAt) {

    public static WebhookSubscriptionDto from(final WebhookSubscription w) {
        return new WebhookSubscriptionDto(w.getId(), w.getRealmId(), w.getName(), w.getUrl(), w.getSecret(),
                w.getSecret() != null && !w.getSecret().isBlank(), w.getEventTypes() == null ? "" : w.getEventTypes(),
                w.isEnabled(), w.getCreationDate() == null ? null : w.getCreationDate().getTime());
    }
}
