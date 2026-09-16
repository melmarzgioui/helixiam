/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.mfa;

import io.helixiam.authorization.domain.mfa.RecoveryCodeEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/** Persistence for single-use MFA recovery codes ({@link RecoveryCodeEntity}). */
@Repository
public interface RecoveryCodeRepository extends JpaRepository<RecoveryCodeEntity, String> {

    List<RecoveryCodeEntity> findAllByUserIdAndUsedFalse(String userId);

    void deleteAllByUserId(String userId);
}
