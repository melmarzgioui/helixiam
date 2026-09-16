package group.mfnr.authorization.repository.mfa;

import group.mfnr.authorization.domain.mfa.HotpCredentialEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/** Persistence for HOTP credentials ({@link HotpCredentialEntity}). */
@Repository
public interface HotpCredentialRepository extends JpaRepository<HotpCredentialEntity, String> {

    Optional<HotpCredentialEntity> findByUserId(String userId);
}
