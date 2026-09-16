package group.mfnr.authorization.amqp.audit.adapter;

import group.mfnr.authorization.amqp.audit.AuditLogPublisher;
import group.mfnr.authorization.amqp.audit.AuditPage;
import group.mfnr.authorization.amqp.audit.AuditQuery;
import group.mfnr.authorization.amqp.audit.AuditRecord;
import group.mfnr.authorization.amqp.support.DtoBridge;
import group.mfnr.authorization.service.audit.AuditLogService;
import org.springframework.stereotype.Component;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link AuditLogPublisher}.
 */
@Component
public class AuditLogLocalAdapter implements AuditLogPublisher {

    private final AuditLogService service;
    private final DtoBridge bridge;

    public AuditLogLocalAdapter(final AuditLogService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    @Override
    public Boolean record(final AuditRecord record) {
        service.record(bridge.to(record, group.mfnr.authorization.domain.audit.AuditRecord.class));
        return Boolean.TRUE;
    }

    @Override
    public AuditPage search(final AuditQuery query) {
        return bridge.to(service.search(
                bridge.to(query, group.mfnr.authorization.domain.audit.AuditQuery.class)),
                AuditPage.class);
    }
}
