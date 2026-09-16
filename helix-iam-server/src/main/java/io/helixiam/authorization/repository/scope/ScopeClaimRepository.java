package io.helixiam.authorization.repository.scope;

import io.helixiam.authorization.domain.scope.ScopeClaim;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** Persistence for scope→claim mappings ({@link ScopeClaim}). */
@Repository
public interface ScopeClaimRepository extends JpaRepository<ScopeClaim, String> {

    List<ScopeClaim> findAllByScopeId(String scopeId);

    Optional<ScopeClaim> findByScopeIdAndClaimId(String scopeId, String claimId);

    long countByScopeId(String scopeId);
}
