package io.helixiam.authorization.amqp.webhook;

/** Helix IAM B6: realm-scoped reference to a webhook subscription (publisher copy). */
public record WebhookRef(String realmId, String id) {
}
