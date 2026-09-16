/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.gdpr;

import io.helixiam.authorization.domain.user.UserCredentials;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/**
 * Helix IAM GDPR Art. 17: a thin, GDPR-owned view over {@code user_credentials} so the anonymize path can
 * stamp the audit-trail columns ({@code anonymized_at}, {@code deleted}) without touching the shared
 * {@code UserCredentials} entity or {@code UserCredentialsRepository} (both owned elsewhere). The PII fields
 * themselves are tombstoned through the entity's existing setters in {@link io.helixiam.authorization.service.gdpr.GdprAdminService}.
 */
public interface GdprUserMutationRepository extends JpaRepository<UserCredentials, String> {

    /** Stamp the anonymization marker columns (best-effort; the columns are additive in schema.sql). */
    @Modifying
    @Query(value = "UPDATE user_credentials SET anonymized_at = CURRENT_TIMESTAMP, deleted = true "
            + "WHERE user_id = :userId", nativeQuery = true)
    int markAnonymized(@Param("userId") String userId);
}
