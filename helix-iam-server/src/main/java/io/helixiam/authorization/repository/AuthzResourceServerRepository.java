package io.helixiam.authorization.repository;

import io.helixiam.authorization.domain.authz.AuthzResourceServerEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/** Helix IAM (Wave 6): persistence for {@link AuthzResourceServerEntity}. */
@Repository
public interface AuthzResourceServerRepository extends JpaRepository<AuthzResourceServerEntity, String> {
    Optional<AuthzResourceServerEntity> findByRealmIdAndClientId(String realmId, String clientId);
}
