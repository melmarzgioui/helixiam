package io.helixiam.authorization.repository.security;

import io.helixiam.authorization.domain.security.LoginFailure;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/** Persistence for the auth-hardening brute-force counter ({@link LoginFailure}). */
@Repository
public interface LoginFailureRepository extends JpaRepository<LoginFailure, String> {

    Optional<LoginFailure> findByRealmIdAndUserId(String realmId, String userId);
}
