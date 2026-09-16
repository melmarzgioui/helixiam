package io.helixiam.authorization.amqp.messaging.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import io.helixiam.authorization.amqp.messaging.DevicePushTokenDto;
import io.helixiam.authorization.amqp.messaging.MessageTemplateDto;
import io.helixiam.authorization.amqp.messaging.MessagingAdminPublisher;
import io.helixiam.authorization.amqp.messaging.MessagingProviderDto;
import io.helixiam.authorization.amqp.messaging.MessagingProviderKey;
import io.helixiam.authorization.amqp.messaging.MessagingProviderWriteDto;
import io.helixiam.authorization.amqp.messaging.ResolveRequest;
import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.authorization.amqp.support.DtoBridge;
import io.helixiam.authorization.service.messaging.DevicePushTokenService;
import io.helixiam.authorization.service.messaging.MessagingAdminService;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link MessagingAdminPublisher}.
 */
@Component
public class MessagingAdminLocalAdapter implements MessagingAdminPublisher {

    private final MessagingAdminService service;
    private final DevicePushTokenService pushTokens;
    private final DtoBridge bridge;

    public MessagingAdminLocalAdapter(final MessagingAdminService service,
                                      final DevicePushTokenService pushTokens,
                                      final DtoBridge bridge) {
        this.service = service;
        this.pushTokens = pushTokens;
        this.bridge = bridge;
    }

    @Override
    public List<MessagingProviderDto> listProviders(final String realmId) {
        return bridge.to(service.listProviders(realmId), new TypeReference<List<MessagingProviderDto>>() { });
    }

    @Override
    public MessagingProviderDto saveProvider(final MessagingProviderWriteDto write) {
        return bridge.to(service.saveProvider(
                bridge.to(write, io.helixiam.authorization.domain.messaging.admin.MessagingProviderWriteDto.class)),
                MessagingProviderDto.class);
    }

    @Override
    public Boolean deleteProvider(final MessagingProviderKey key) {
        return service.deleteProvider(key.realmId(), key.channel(), key.driver());
    }

    @Override
    public List<ResolvedProviderDto> enabledProviders(final ResolveRequest request) {
        return bridge.to(service.enabledProviders(request.realmId(), request.channel()),
                new TypeReference<List<ResolvedProviderDto>>() { });
    }

    @Override
    public List<MessageTemplateDto> listTemplates(final String realmId) {
        return bridge.to(service.listTemplates(realmId), new TypeReference<List<MessageTemplateDto>>() { });
    }

    @Override
    public MessageTemplateDto saveTemplate(final MessageTemplateDto dto) {
        return bridge.to(service.saveTemplate(
                bridge.to(dto, io.helixiam.authorization.domain.messaging.admin.MessageTemplateDto.class)),
                MessageTemplateDto.class);
    }

    @Override
    public DevicePushTokenDto registerPushToken(final DevicePushTokenDto dto) {
        return bridge.to(pushTokens.register(
                bridge.to(dto, io.helixiam.authorization.domain.messaging.admin.DevicePushTokenDto.class)),
                DevicePushTokenDto.class);
    }

    @Override
    public List<DevicePushTokenDto> listPushTokens(final PushTokenQuery query) {
        return bridge.to(pushTokens.list(query.realmId(), query.userId()),
                new TypeReference<List<DevicePushTokenDto>>() { });
    }
}
