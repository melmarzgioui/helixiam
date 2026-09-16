package io.helixiam.authorization.amqp.client.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import io.helixiam.authorization.amqp.client.ClientAdminPublisher;
import io.helixiam.authorization.amqp.client.ClientDto;
import io.helixiam.authorization.amqp.client.ClientRef;
import io.helixiam.authorization.amqp.client.ClientWriteDto;
import io.helixiam.authorization.amqp.support.DtoBridge;
import io.helixiam.authorization.service.client.ClientAdminService;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link ClientAdminPublisher}.
 */
@Component
public class ClientAdminLocalAdapter implements ClientAdminPublisher {

    private final ClientAdminService service;
    private final DtoBridge bridge;

    public ClientAdminLocalAdapter(final ClientAdminService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    @Override
    public List<ClientDto> list(final String realmId) {
        return bridge.to(service.list(realmId), new TypeReference<List<ClientDto>>() { });
    }

    @Override
    public ClientDto get(final ClientRef ref) {
        return bridge.to(service.get(ref.realmId(), ref.id()).orElse(null), ClientDto.class);
    }

    @Override
    public ClientDto create(final ClientWriteDto write) {
        return bridge.to(service.create(
                bridge.to(write, io.helixiam.authorization.domain.client.admin.ClientWriteDto.class)),
                ClientDto.class);
    }

    @Override
    public ClientDto update(final ClientWriteDto write) {
        return bridge.to(service.update(
                bridge.to(write, io.helixiam.authorization.domain.client.admin.ClientWriteDto.class)).orElse(null),
                ClientDto.class);
    }

    @Override
    public Boolean delete(final ClientRef ref) {
        return service.delete(ref.realmId(), ref.id());
    }

    @Override
    public ClientDto regenerate(final ClientRef ref) {
        return bridge.to(service.regenerateSecret(ref.realmId(), ref.id()).orElse(null), ClientDto.class);
    }

    @Override
    public ClientDto reveal(final ClientRef ref) {
        return bridge.to(service.reveal(ref.realmId(), ref.id()).orElse(null), ClientDto.class);
    }
}
