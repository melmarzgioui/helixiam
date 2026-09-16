package group.mfnr.authorization.repository.realm;

import group.mfnr.authorization.domain.realm.AuthFlowEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** Persistence for per-realm authentication flows ({@link AuthFlowEntity}). */
@Repository
public interface AuthFlowRepository extends JpaRepository<AuthFlowEntity, String> {

    Optional<AuthFlowEntity> findFirstByRealmIdAndAlias(String realmId, String alias);

    /** All of a realm's named flows — backs the editor's flow picker (Helix IAM: per-client flow overrides). */
    List<AuthFlowEntity> findAllByRealmIdOrderByCreationDateAsc(String realmId);
}
