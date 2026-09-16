package group.mfnr.authorization.repository;

import group.mfnr.authorization.domain.client.role.ClientServiceAccountRoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** Helix IAM (Wave 4): persistence for service-account role grants ({@link ClientServiceAccountRoleEntity}). */
@Repository
public interface ClientServiceAccountRoleRepository extends JpaRepository<ClientServiceAccountRoleEntity, String> {

    List<ClientServiceAccountRoleEntity> findAllByRealmIdAndClientIdOrderByRoleName(String realmId, String clientId);

    List<ClientServiceAccountRoleEntity> findAllByClientId(String clientId);

    Optional<ClientServiceAccountRoleEntity> findByRealmIdAndClientIdAndRoleNameAndRoleType(
            String realmId, String clientId, String roleName, String roleType);
}
