package io.helixiam.authorization.amqp.httpsession.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import io.helixiam.authorization.amqp.httpsession.HttpSessionRecord;
import io.helixiam.authorization.amqp.httpsession.HttpSessionStorePublisher;
import io.helixiam.authorization.amqp.support.DtoBridge;
import io.helixiam.authorization.service.httpsession.HttpSessionStoreService;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link HttpSessionStorePublisher}.
 */
@Component
public class HttpSessionStoreLocalAdapter implements HttpSessionStorePublisher {

    private final HttpSessionStoreService service;
    private final DtoBridge bridge;

    public HttpSessionStoreLocalAdapter(final HttpSessionStoreService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    @Override
    public Boolean save(final HttpSessionRecord record) {
        return service.save(
                bridge.to(record, io.helixiam.authorization.domain.httpsession.admin.HttpSessionRecord.class));
    }

    @Override
    public HttpSessionRecord findById(final String sessionId) {
        return bridge.to(service.findById(sessionId), HttpSessionRecord.class);
    }

    @Override
    public Boolean deleteById(final String sessionId) {
        return service.deleteById(sessionId);
    }

    @Override
    public List<HttpSessionRecord> findByPrincipal(final String principalName) {
        return bridge.to(service.findByPrincipal(principalName),
                new TypeReference<List<HttpSessionRecord>>() { });
    }

    @Override
    public Integer deleteByPrincipal(final String principalName) {
        return service.deleteByPrincipal(principalName);
    }
}
