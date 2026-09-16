package group.mfnr.authorization.repository.mfa;

import group.mfnr.authorization.domain.mfa.RecoveryCodeEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/** Persistence for single-use MFA recovery codes ({@link RecoveryCodeEntity}). */
@Repository
public interface RecoveryCodeRepository extends JpaRepository<RecoveryCodeEntity, String> {

    List<RecoveryCodeEntity> findAllByUserIdAndUsedFalse(String userId);

    void deleteAllByUserId(String userId);
}
