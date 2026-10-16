/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.tenant;

import io.helixiam.authorization.domain.tenant.TenantUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface TenantUserRepository extends JpaRepository<TenantUser, String> {

    Optional<TenantUser> findByTenantIdAndUserId(final String tenantId, final String userId);

    List<TenantUser> findAllByTenantId(final String tenantId);

    List<TenantUser> findAllByUserId(final String userId);

    /**
     * Round 6: the realms a user belongs to, without loading the entities (their profile collection is shared between
     * a user's memberships, which Hibernate refuses to flush in a session that loaded two of them).
     */
    @org.springframework.data.jpa.repository.Query("select t.tenantId from TenantUser t where t.userId = :userId")
    List<String> findTenantIdsByUserId(@org.springframework.data.repository.query.Param("userId") String userId);

    boolean existsByTenantIdAndUserId(String tenantId, String userId);
}
