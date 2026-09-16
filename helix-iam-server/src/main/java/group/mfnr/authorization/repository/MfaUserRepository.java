package group.mfnr.authorization.repository;

import group.mfnr.authorization.domain.user.MfaUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MfaUserRepository extends JpaRepository<MfaUser, String> {
}
