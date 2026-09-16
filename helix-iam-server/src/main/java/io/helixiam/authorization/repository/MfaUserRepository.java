package io.helixiam.authorization.repository;

import io.helixiam.authorization.domain.user.MfaUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MfaUserRepository extends JpaRepository<MfaUser, String> {
}
