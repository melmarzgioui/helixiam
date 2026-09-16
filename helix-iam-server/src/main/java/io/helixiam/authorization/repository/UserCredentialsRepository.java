package io.helixiam.authorization.repository;

import io.helixiam.authorization.domain.user.UserCredentials;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserCredentialsRepository extends JpaRepository<UserCredentials, String> {

    Optional<UserCredentials> findByUsername(final String username);

    Optional<UserCredentials> findByEmail(final String email);

    Optional<UserCredentials> findByUserId(final String userId);
}