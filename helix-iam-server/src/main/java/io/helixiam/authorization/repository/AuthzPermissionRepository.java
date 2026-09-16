package io.helixiam.authorization.repository;

import io.helixiam.authorization.domain.authz.AuthzPermissionEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** Helix IAM (Wave 6): persistence for {@link AuthzPermissionEntity}. */
@Repository
public interface AuthzPermissionRepository extends JpaRepository<AuthzPermissionEntity, String> {
    List<AuthzPermissionEntity> findAllByRealmIdAndClientIdOrderByName(String realmId, String clientId);
    Optional<AuthzPermissionEntity> findByRealmIdAndClientIdAndName(String realmId, String clientId, String name);
    boolean existsByRealmIdAndClientIdAndName(String realmId, String clientId, String name);
}
