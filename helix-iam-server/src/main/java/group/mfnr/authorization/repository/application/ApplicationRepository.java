package group.mfnr.authorization.repository.application;

import group.mfnr.authorization.domain.application.ApplicationEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Helix IAM: persistence for per-realm Applications. {@code findById} (key = {@code realmId|name}) is the
 * resolution-walk lookup used by the subject-claim + login-flow resolvers.
 */
@Repository
public interface ApplicationRepository extends JpaRepository<ApplicationEntity, String> {

    List<ApplicationEntity> findAllByRealmId(String realmId);

    Optional<ApplicationEntity> findByRealmIdAndName(String realmId, String name);

    boolean existsByRealmIdAndName(String realmId, String name);

    void deleteByRealmIdAndName(String realmId, String name);
}
