package io.helixiam.authorization.amqp.audit;

/** Helix IAM B3: publisher-side copy of a persisted audit event (two-copy DTO; subscriber mirror in domain.audit). */
public record AuditRecord(String ts, String kind, String category, String type, String realm, String actor,
                          String sourceIp, String resourceType, String resourceId, String outcome, String detail) {
}
