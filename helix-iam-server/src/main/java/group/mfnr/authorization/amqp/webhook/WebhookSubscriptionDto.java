package group.mfnr.authorization.amqp.webhook;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM B6: publisher-side copy of the subscriber's webhook DTO (two-copy, same field order for
 * Jackson-over-AMQP). The {@code secret} crosses the internal seam so the dispatcher can HMAC-sign
 * payloads; the admin controller nulls it before returning to the console ({@code secretSet} stays).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record WebhookSubscriptionDto(String id, String realmId, String name, String url, String secret,
                                     boolean secretSet, String eventTypes, boolean enabled, Long createdAt) {
}
