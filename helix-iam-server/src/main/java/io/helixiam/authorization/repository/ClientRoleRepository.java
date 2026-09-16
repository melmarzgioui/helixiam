package io.helixiam.authorization.repository;

import io.helixiam.authorization.domain.client.role.ClientRoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** Helix IAM (Wave 4): persistence for client roles ({@link ClientRoleEntity}). */
@Repository
public interface ClientRoleRepository extends JpaRepository<ClientRoleEntity, String> {

    List<ClientRoleEntity> findAllByRealmIdAndClientIdOrderByName(String realmId, String clientId);

    Optional<ClientRoleEntity> findByRealmIdAndClientIdAndName(String realmId, String clientId, String name);

    boolean existsByRealmIdAndClientIdAndName(String realmId, String clientId, String name);
}
