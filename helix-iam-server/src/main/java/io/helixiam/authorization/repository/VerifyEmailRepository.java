package io.helixiam.authorization.repository;

import io.helixiam.authorization.domain.user.VerifyEmail;
import org.springframework.data.jpa.repository.JpaRepository;

public interface VerifyEmailRepository extends JpaRepository<VerifyEmail, String> {
}
