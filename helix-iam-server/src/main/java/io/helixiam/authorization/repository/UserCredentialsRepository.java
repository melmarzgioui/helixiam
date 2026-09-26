/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository;

import io.helixiam.authorization.domain.user.UserCredentials;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserCredentialsRepository extends JpaRepository<UserCredentials, String> {

    Optional<UserCredentials> findByUsername(final String username);

    Optional<UserCredentials> findByEmail(final String email);

    Optional<UserCredentials> findByUserId(final String userId);

    /**
     * 1.0 item 6: atomically records an accepted TOTP time step, only if it is later than the last one.
     * Returns 1 when the step was accepted, 0 for a replay (same or earlier step, incl. a concurrent use).
     */
    @org.springframework.data.jpa.repository.Modifying
    @org.springframework.transaction.annotation.Transactional
    @org.springframework.data.jpa.repository.Query(value = "UPDATE user_credentials SET mfa_last_step = :step "
            + "WHERE user_id = :userId AND (mfa_last_step IS NULL OR mfa_last_step < :step)", nativeQuery = true)
    int advanceMfaStep(@org.springframework.data.repository.query.Param("userId") String userId,
                       @org.springframework.data.repository.query.Param("step") long step);
}