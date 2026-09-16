package group.mfnr.authorization.repository.scope;

import group.mfnr.authorization.domain.scope.ClaimDef;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/** Persistence for the realm's claim catalogue ({@link ClaimDef}). */
@Repository
public interface ClaimDefRepository extends JpaRepository<ClaimDef, String> {

    List<ClaimDef> findAllByTenantId(String tenantId);

    boolean existsByTenantIdAndClaimKey(String tenantId, String claimKey);

    long countByTenantId(String tenantId);
}
