package group.mfnr.authorization.repository.audit;

import group.mfnr.authorization.domain.audit.AuditLogEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/** Helix IAM B3: persistence + filtered search for the audit log. Null filters match everything. */
@Repository
public interface AuditLogRepository extends JpaRepository<AuditLogEntity, String> {

    // The actor filter is matched against a caller-supplied, already-lowercased LIKE pattern
    // (e.g. "%alice%") rather than wrapping the bind param in LOWER()/CONCAT — that avoids Postgres
    // inferring an untyped null bind as bytea ("function lower(bytea) does not exist").
    @Query("""
            SELECT a FROM AuditLogEntity a
            WHERE a.realmId = :realm
              AND (:type IS NULL OR a.type = :type)
              AND (:category IS NULL OR a.category = :category)
              AND (:outcome IS NULL OR a.outcome = :outcome)
              AND (:actorLike IS NULL OR LOWER(a.actor) LIKE :actorLike)
            ORDER BY a.occurredAt DESC
            """)
    Page<AuditLogEntity> search(@Param("realm") String realm, @Param("type") String type,
                                @Param("category") String category, @Param("outcome") String outcome,
                                @Param("actorLike") String actorLike, Pageable pageable);
}
