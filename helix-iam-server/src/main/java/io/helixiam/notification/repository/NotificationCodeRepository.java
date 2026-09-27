/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.notification.repository;

import io.helixiam.notification.domain.NotificationCode;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface NotificationCodeRepository extends JpaRepository<NotificationCode, String> {
    Optional<NotificationCode> findByIdentifierAndType(final String identifier, final String type);
    Optional<NotificationCode> findByCodeAndType(final String code, final String type);

    /**
     * Uses up a code: deletes it and returns 1, or 0 when it is already gone (used by a concurrent request). Makes
     * the codes single-use even under a race.
     */
    @org.springframework.data.jpa.repository.Modifying(clearAutomatically = true, flushAutomatically = true)
    @org.springframework.data.jpa.repository.Query("DELETE FROM NotificationCode c WHERE c.code = :code AND c.type = :type")
    int consume(@org.springframework.data.repository.query.Param("code") String code,
                @org.springframework.data.repository.query.Param("type") String type);
}
