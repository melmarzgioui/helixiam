/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository;

import io.helixiam.authorization.domain.user.UserCredentials;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserCredentialsRepository extends JpaRepository<UserCredentials, String> {



    Optional<UserCredentials> findByUserId(final String userId);

    // No global findByUsername/findByEmail: usernames and emails are unique per realm only, so every lookup by
    // name must name the realm (a global lookup would let one realm's user sign in at another realm).

    /** A user of {@code realmId} by username (usernames are unique per realm). */
    Optional<UserCredentials> findByRealmIdAndUsername(final String realmId, final String username);

    /** A user of {@code realmId} by email address (emails are unique per realm). */
    Optional<UserCredentials> findByRealmIdAndEmail(final String realmId, final String email);

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