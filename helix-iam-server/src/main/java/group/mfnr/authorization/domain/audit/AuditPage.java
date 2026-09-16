package group.mfnr.authorization.domain.audit;

import java.util.List;

/** Helix IAM B3: a page of audit events plus the total match count. Two-copy DTO (publisher mirror). */
public record AuditPage(List<AuditRecord> items, long total, int page, int size) {
}
