package io.helixiam.authorization.repository;

import io.helixiam.authorization.domain.user.ChangePassword;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ChangePasswordRepository extends JpaRepository<ChangePassword, String> {

}