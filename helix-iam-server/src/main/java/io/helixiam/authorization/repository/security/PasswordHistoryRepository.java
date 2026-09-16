/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.security;

import io.helixiam.authorization.domain.security.PasswordHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/** Persistence for the auth-hardening password-reuse history ({@link PasswordHistory}). */
@Repository
public interface PasswordHistoryRepository extends JpaRepository<PasswordHistory, String> {

    /** A user's prior password hashes, newest first. */
    List<PasswordHistory> findByUserIdOrderByCreationDateDesc(String userId);
}
