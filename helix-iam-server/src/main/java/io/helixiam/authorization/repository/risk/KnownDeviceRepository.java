package io.helixiam.authorization.repository.risk;

import io.helixiam.authorization.domain.risk.KnownDevice;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/** Persistence for the per-user remembered-device history ({@link KnownDevice}). */
@Repository
public interface KnownDeviceRepository extends JpaRepository<KnownDevice, String> {

    Optional<KnownDevice> findByRealmIdAndUserIdAndFingerprint(String realmId, String userId, String fingerprint);

    boolean existsByRealmIdAndUserId(String realmId, String userId);
}
