package group.mfnr.authorization.repository.scope;

import group.mfnr.authorization.domain.scope.ClientScope;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/** Persistence for realm client scopes ({@link ClientScope}). */
@Repository
public interface ClientScopeRepository extends JpaRepository<ClientScope, String> {

    List<ClientScope> findAllByTenantId(String tenantId);

    boolean existsByTenantIdAndName(String tenantId, String name);

    long countByTenantId(String tenantId);
}
