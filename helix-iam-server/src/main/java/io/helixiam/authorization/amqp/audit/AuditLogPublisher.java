package io.helixiam.authorization.amqp.audit;


/**
 * Helix IAM B3: the audit log's seam onto the persisted store (owned by the subscriber). {@code record}
 * persists an emitted event; {@code search} answers the console's filtered query. Routing keys are dotted
 * (the subscriber binds the dash form).
 */
public interface AuditLogPublisher {

    String EXCHANGE_AUTHORIZATION_AUDIT = "exchange-authorization-audit";
    String AUDIT_RECORD = "authorization.audit.record";
    String AUDIT_SEARCH = "authorization.audit.search";

    Boolean record(AuditRecord record);

    AuditPage search(AuditQuery query);
}
