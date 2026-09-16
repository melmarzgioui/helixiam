package io.helixiam.authorization.amqp.messaging;


import java.util.List;

/**
 * Helix IAM notifications (N2): the messaging-admin API's seam onto the provider/template store (owned by
 * the subscriber). Routing keys are single tokens (dotted) for unambiguous queue binding.
 */
public interface MessagingAdminPublisher {

    String EXCHANGE_AUTHORIZATION_MESSAGING_ADMIN = "exchange-authorization-messaging-admin";
    String PROVIDER_LIST = "authorization.messaging.provider.list";
    String PROVIDER_SAVE = "authorization.messaging.provider.save";
    String PROVIDER_DELETE = "authorization.messaging.provider.delete";
    String PROVIDER_RESOLVE = "authorization.messaging.provider.resolve";
    String TEMPLATE_LIST = "authorization.messaging.template.list";
    String TEMPLATE_SAVE = "authorization.messaging.template.save";
    String PUSH_TOKEN_REGISTER = "authorization.messaging.pushtoken.register";
    String PUSH_TOKEN_LIST = "authorization.messaging.pushtoken.list";

    /** Key for a per-user push-token lookup (N6c). */
    record PushTokenQuery(String realmId, String userId) {
    }

    List<MessagingProviderDto> listProviders(String realmId);

    MessagingProviderDto saveProvider(MessagingProviderWriteDto write);

    Boolean deleteProvider(MessagingProviderKey key);

    /** SENDER path (N3): the realm's enabled providers for a channel, with secrets. Server-to-server only. */
    List<ResolvedProviderDto> enabledProviders(ResolveRequest request);

    List<MessageTemplateDto> listTemplates(String realmId);

    MessageTemplateDto saveTemplate(MessageTemplateDto dto);

    /** Register (idempotent) a user's push device token (N6c). */
    DevicePushTokenDto registerPushToken(DevicePushTokenDto dto);

    /** The push device tokens registered for a user in a realm (N6c). */
    List<DevicePushTokenDto> listPushTokens(PushTokenQuery query);
}
