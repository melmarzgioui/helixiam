package group.mfnr.authorization.amqp.mapper.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import group.mfnr.authorization.amqp.mapper.ClientMapperPublisher;
import group.mfnr.authorization.amqp.mapper.MapperRef;
import group.mfnr.authorization.amqp.mapper.ProtocolMapperDto;
import group.mfnr.authorization.amqp.mapper.ProtocolMapperWriteDto;
import group.mfnr.authorization.amqp.support.DtoBridge;
import group.mfnr.authorization.service.client.ClientMapperAdminService;
import group.mfnr.authorization.support.RealmScopedKey;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link ClientMapperPublisher}.
 */
@Component
public class ClientMapperLocalAdapter implements ClientMapperPublisher {

    private final ClientMapperAdminService service;
    private final DtoBridge bridge;

    public ClientMapperLocalAdapter(final ClientMapperAdminService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    @Override
    public List<ProtocolMapperDto> list(final MapperRef ref) {
        return bridge.to(service.list(ref.realmId(), ref.clientId()),
                new TypeReference<List<ProtocolMapperDto>>() { });
    }

    @Override
    public ProtocolMapperDto create(final ProtocolMapperWriteDto write) {
        return bridge.to(service.create(
                bridge.to(write, group.mfnr.authorization.domain.client.mapper.ProtocolMapperWriteDto.class)),
                ProtocolMapperDto.class);
    }

    @Override
    public ProtocolMapperDto update(final ProtocolMapperWriteDto write) {
        return bridge.to(service.update(
                bridge.to(write, group.mfnr.authorization.domain.client.mapper.ProtocolMapperWriteDto.class))
                .orElse(null), ProtocolMapperDto.class);
    }

    @Override
    public Boolean delete(final MapperRef ref) {
        return service.delete(ref.realmId(), ref.clientId(), ref.mapperId());
    }

    @Override
    public List<ProtocolMapperDto> forClient(final String clientId) {
        final String[] parts = RealmScopedKey.split(clientId);
        return bridge.to(service.mappersForClient(parts[0], parts[1]),
                new TypeReference<List<ProtocolMapperDto>>() { });
    }
}
