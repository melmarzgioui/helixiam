package group.mfnr.authorization.amqp.authzstore.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import group.mfnr.authorization.amqp.authzstore.AuthorizationRecord;
import group.mfnr.authorization.amqp.authzstore.AuthorizationStorePublisher;
import group.mfnr.authorization.amqp.support.DtoBridge;
import group.mfnr.authorization.service.authzstore.AuthorizationStoreService;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link AuthorizationStorePublisher}.
 */
@Component
public class AuthorizationStoreLocalAdapter implements AuthorizationStorePublisher {

    private final AuthorizationStoreService service;
    private final DtoBridge bridge;

    public AuthorizationStoreLocalAdapter(final AuthorizationStoreService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    @Override
    public Boolean save(final AuthorizationRecord record) {
        return service.save(
                bridge.to(record, group.mfnr.authorization.domain.authzstore.admin.AuthorizationRecord.class));
    }

    @Override
    public Boolean remove(final RemoveRequest request) {
        return service.remove(bridge.to(request,
                group.mfnr.authorization.domain.authzstore.admin.AuthorizationRemoveRequest.class));
    }

    @Override
    public AuthorizationRecord findById(final String id) {
        return bridge.to(service.findById(id), AuthorizationRecord.class);
    }

    @Override
    public AuthorizationRecord findByToken(final String tokenKey) {
        return bridge.to(service.findByToken(tokenKey), AuthorizationRecord.class);
    }

    @Override
    public List<AuthorizationRecord> listAll(final String marker) {
        return bridge.to(service.listAll(), new TypeReference<List<AuthorizationRecord>>() { });
    }
}
