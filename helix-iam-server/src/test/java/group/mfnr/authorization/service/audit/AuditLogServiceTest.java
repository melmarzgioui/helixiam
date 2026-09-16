package group.mfnr.authorization.service.audit;

import group.mfnr.authorization.domain.audit.AuditLogEntity;
import group.mfnr.authorization.domain.audit.AuditPage;
import group.mfnr.authorization.domain.audit.AuditQuery;
import group.mfnr.authorization.domain.audit.AuditRecord;
import group.mfnr.authorization.repository.audit.AuditLogRepository;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Helix IAM B3: the audit-log persistence + search service. */
class AuditLogServiceTest {

    private final AuditLogRepository repo = mock(AuditLogRepository.class);
    private final AuditLogService service = new AuditLogService(repo);

    private static AuditRecord event(final String realm) {
        return new AuditRecord("2026-06-29T10:00:00Z", "audit", "AUTHN", "LOGIN_SUCCESS", realm,
                "alice", "1.2.3.4", null, null, "SUCCESS", null);
    }

    @Test
    void recordPersistsAnEventWithARealm() {
        service.record(event("master"));
        verify(repo).save(any(AuditLogEntity.class));
    }

    @Test
    void recordSkipsRealmlessEvents() {
        service.record(event(null));
        verify(repo, never()).save(any());
    }

    @Test
    void searchMapsEntitiesToRecordsWithTotal() {
        final AuditLogEntity row = AuditLogEntity.from(event("master"));
        when(repo.search(eq("master"), isNull(), isNull(), isNull(), isNull(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(row), PageRequest.of(0, 50), 1));

        final AuditPage page = service.search(new AuditQuery("master", null, null, null, null, 0, 50));

        assertThat(page.total()).isEqualTo(1);
        assertThat(page.items()).hasSize(1);
        assertThat(page.items().get(0).type()).isEqualTo("LOGIN_SUCCESS");
        assertThat(page.items().get(0).actor()).isEqualTo("alice");
    }

    @Test
    void searchClampsPageSizeAndPassesFilters() {
        when(repo.search(eq("master"), eq("LOGIN_FAILURE"), isNull(), eq("FAILURE"), isNull(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(), PageRequest.of(0, 200), 0));

        final AuditPage page = service.search(new AuditQuery("master", "LOGIN_FAILURE", "", "FAILURE", "", 0, 9999));

        assertThat(page.size()).isEqualTo(200); // clamped to MAX_SIZE
        verify(repo).search(eq("master"), eq("LOGIN_FAILURE"), isNull(), eq("FAILURE"), isNull(), any(Pageable.class));
    }
}
