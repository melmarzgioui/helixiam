package io.helixiam.authorization.repository.gdpr;

import io.helixiam.authorization.domain.gdpr.ConsentLedgerEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/** Helix IAM GDPR Art. 7: persistence for the per-user, per-client consent ledger. */
@Repository
public interface ConsentLedgerRepository extends JpaRepository<ConsentLedgerEntity, String> {

    List<ConsentLedgerEntity> findAllByRealmIdAndUserIdOrderByGrantedAtDesc(String realmId, String userId);

    List<ConsentLedgerEntity> findAllByUserId(String userId);

    /** Active (not-yet-withdrawn) rows for one client — the targets of a withdraw. */
    List<ConsentLedgerEntity> findAllByRealmIdAndUserIdAndClientIdAndWithdrawnAtIsNull(
            String realmId, String userId, String clientId);
}
