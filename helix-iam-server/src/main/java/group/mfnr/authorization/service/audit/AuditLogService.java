package group.mfnr.authorization.service.audit;

import group.mfnr.authorization.domain.audit.AuditLogEntity;
import group.mfnr.authorization.domain.audit.AuditPage;
import group.mfnr.authorization.domain.audit.AuditQuery;
import group.mfnr.authorization.domain.audit.AuditRecord;
import group.mfnr.authorization.repository.audit.AuditLogRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/** Helix IAM B3: persists incoming audit events and answers filtered, paged searches for the console. */
@Service
public class AuditLogService {

    private static final int MAX_SIZE = 200;

    private final AuditLogRepository repository;

    public AuditLogService(final AuditLogRepository repository) {
        this.repository = repository;
    }

    @Transactional
    public void record(final AuditRecord record) {
        if (record == null || record.realm() == null || record.realm().isBlank()) {
            return; // never persist a realm-less event (it could not be searched by realm anyway)
        }
        repository.save(AuditLogEntity.from(record));
    }

    @Transactional(readOnly = true)
    public AuditPage search(final AuditQuery q) {
        final int page = Math.max(0, q.page());
        final int size = q.size() <= 0 ? 50 : Math.min(q.size(), MAX_SIZE);
        final String actor = blankToNull(q.actor());
        final String actorLike = actor == null ? null : "%" + actor.toLowerCase(java.util.Locale.ROOT) + "%";
        final Page<AuditLogEntity> result = repository.search(
                q.realm(), blankToNull(q.type()), blankToNull(q.category()), blankToNull(q.outcome()),
                actorLike, PageRequest.of(page, size));
        final List<AuditRecord> items = result.getContent().stream().map(AuditLogEntity::toRecord).toList();
        return new AuditPage(items, result.getTotalElements(), page, size);
    }

    private static String blankToNull(final String v) {
        return v == null || v.isBlank() ? null : v;
    }
}
