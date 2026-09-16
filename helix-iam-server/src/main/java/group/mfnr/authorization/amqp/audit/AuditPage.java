package group.mfnr.authorization.amqp.audit;

import java.util.List;

/** Helix IAM B3: publisher-side copy of a page of audit events + total. */
public record AuditPage(List<AuditRecord> items, long total, int page, int size) {
}
