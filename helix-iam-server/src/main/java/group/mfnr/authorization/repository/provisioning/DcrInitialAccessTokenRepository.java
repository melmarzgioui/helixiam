package group.mfnr.authorization.repository.provisioning;

import group.mfnr.authorization.domain.provisioning.DcrInitialAccessToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/** Persistence for {@link DcrInitialAccessToken} (RFC 7591 §1.2 single-use registration ticket). */
@Repository
public interface DcrInitialAccessTokenRepository extends JpaRepository<DcrInitialAccessToken, String> {

    Optional<DcrInitialAccessToken> findByRealmIdAndTokenHash(String realmId, String tokenHash);
}
