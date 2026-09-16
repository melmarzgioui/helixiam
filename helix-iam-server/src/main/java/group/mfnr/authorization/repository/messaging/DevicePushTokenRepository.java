package group.mfnr.authorization.repository.messaging;

import group.mfnr.authorization.domain.messaging.DevicePushToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** Persistence for {@link DevicePushToken} (per-realm, per-user push device tokens). */
@Repository
public interface DevicePushTokenRepository extends JpaRepository<DevicePushToken, String> {

    List<DevicePushToken> findByRealmIdAndUserId(String realmId, String userId);

    Optional<DevicePushToken> findByRealmIdAndUserIdAndPlatformAndToken(String realmId, String userId,
                                                                        String platform, String token);
}
