package group.mfnr.authorization.repository;

import group.mfnr.authorization.domain.authz.AuthzScopeEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** Helix IAM (Wave 6): persistence for {@link AuthzScopeEntity}. */
@Repository
public interface AuthzScopeRepository extends JpaRepository<AuthzScopeEntity, String> {
    List<AuthzScopeEntity> findAllByRealmIdAndClientIdOrderByName(String realmId, String clientId);
    Optional<AuthzScopeEntity> findByRealmIdAndClientIdAndName(String realmId, String clientId, String name);
    boolean existsByRealmIdAndClientIdAndName(String realmId, String clientId, String name);
}
