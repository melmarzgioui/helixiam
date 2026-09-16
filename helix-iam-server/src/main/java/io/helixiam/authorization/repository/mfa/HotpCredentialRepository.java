/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.mfa;

import io.helixiam.authorization.domain.mfa.HotpCredentialEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/** Persistence for HOTP credentials ({@link HotpCredentialEntity}). */
@Repository
public interface HotpCredentialRepository extends JpaRepository<HotpCredentialEntity, String> {

    Optional<HotpCredentialEntity> findByUserId(String userId);
}
