package io.helixiam.authorization.repository.risk;

import io.helixiam.authorization.domain.risk.KnownLoginIp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** Persistence for the per-user recent-login-IP history ({@link KnownLoginIp}). */
@Repository
public interface KnownLoginIpRepository extends JpaRepository<KnownLoginIp, String> {

    Optional<KnownLoginIp> findByRealmIdAndUserIdAndIp(String realmId, String userId, String ip);

    boolean existsByRealmIdAndUserId(String realmId, String userId);

    List<KnownLoginIp> findAllByRealmIdAndUserId(String realmId, String userId);
}
