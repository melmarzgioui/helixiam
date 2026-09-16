package group.mfnr.authorization.repository.security;

import group.mfnr.authorization.domain.security.PasswordHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/** Persistence for the auth-hardening password-reuse history ({@link PasswordHistory}). */
@Repository
public interface PasswordHistoryRepository extends JpaRepository<PasswordHistory, String> {

    /** A user's prior password hashes, newest first. */
    List<PasswordHistory> findByUserIdOrderByCreationDateDesc(String userId);
}
