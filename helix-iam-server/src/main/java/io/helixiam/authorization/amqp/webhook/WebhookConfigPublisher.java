package io.helixiam.authorization.amqp.webhook;


import java.util.List;

/**
 * Helix IAM B6: the admin API's + event dispatcher's seam onto the per-realm webhook store (subscriber).
 * {@code list}/{@code save}/{@code delete} back the console; {@code active} feeds the dispatcher the
 * enabled subscriptions (with their signing secret). All-dot routing keys for the dash→dot binding.
 */
public interface WebhookConfigPublisher {

    String EXCHANGE_AUTHORIZATION_WEBHOOKS = "exchange-authorization-webhooks";
    String WEBHOOK_LIST = "authorization.webhooks.list";
    String WEBHOOK_ACTIVE = "authorization.webhooks.active";
    String WEBHOOK_SAVE = "authorization.webhooks.save";
    String WEBHOOK_DELETE = "authorization.webhooks.delete";

    List<WebhookSubscriptionDto> list(final String realmId);

    List<WebhookSubscriptionDto> active(final String realmId);

    WebhookSubscriptionDto save(final WebhookSubscriptionDto dto);

    Boolean delete(final WebhookRef ref);
}
