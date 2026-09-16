package group.mfnr.authorization.repository;

import group.mfnr.authorization.domain.user.VerifyEmail;
import org.springframework.data.jpa.repository.JpaRepository;

public interface VerifyEmailRepository extends JpaRepository<VerifyEmail, String> {
}
