package group.mfnr.authorization.repository;

import group.mfnr.authorization.domain.user.ChangePassword;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ChangePasswordRepository extends JpaRepository<ChangePassword, String> {

}