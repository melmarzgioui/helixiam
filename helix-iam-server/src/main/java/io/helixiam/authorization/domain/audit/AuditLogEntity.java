package io.helixiam.authorization.domain.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.util.Date;
import java.util.UUID;

/** Helix IAM B3: one persisted audit-log row. Maps the {@code audit_log} table. */
@Entity
@Table(name = "audit_log")
public class AuditLogEntity {

    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "occurred_at")
    private Date occurredAt;

    @Column(name = "ts_iso")
    private String tsIso;

    @Column(name = "kind")
    private String kind;

    @Column(name = "category")
    private String category;

    @Column(name = "type")
    private String type;

    @Column(name = "realm_id")
    private String realmId;

    @Column(name = "actor")
    private String actor;

    @Column(name = "source_ip")
    private String sourceIp;

    @Column(name = "resource_type")
    private String resourceType;

    @Column(name = "resource_id")
    private String resourceId;

    @Column(name = "outcome")
    private String outcome;

    @Column(name = "detail")
    private String detail;

    public AuditLogEntity() {
    }

    public static AuditLogEntity from(final AuditRecord r) {
        final AuditLogEntity e = new AuditLogEntity();
        e.id = UUID.randomUUID().toString();
        e.occurredAt = new Date();
        e.tsIso = trim(r.ts(), 40);
        e.kind = trim(r.kind(), 32);
        e.category = trim(r.category(), 32);
        e.type = trim(r.type(), 96);
        e.realmId = trim(r.realm(), 255);
        e.actor = trim(r.actor(), 255);
        e.sourceIp = trim(r.sourceIp(), 64);
        e.resourceType = trim(r.resourceType(), 96);
        e.resourceId = trim(r.resourceId(), 255);
        e.outcome = trim(r.outcome(), 32);
        e.detail = trim(r.detail(), 2000);
        return e;
    }

    public AuditRecord toRecord() {
        return new AuditRecord(tsIso, kind, category, type, realmId, actor, sourceIp, resourceType, resourceId, outcome, detail);
    }

    private static String trim(final String v, final int max) {
        if (v == null) {
            return null;
        }
        return v.length() <= max ? v : v.substring(0, max);
    }

    public String getId() {
        return id;
    }

    public String getType() {
        return type;
    }
}
