/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository;

import io.helixiam.authorization.domain.user.UserRoles;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserRolesRepository extends JpaRepository<UserRoles, String> {
    Optional<UserRoles> findByTenantIdAndName(final String tenantId, final String name);

    List<UserRoles> findAllByTenantId(final String tenantId);

    boolean existsByTenantIdAndName(final String tenantId, final String name);

    /** The realm's default role (auto-assigned to new users), if one is designated. */
    Optional<UserRoles> findFirstByTenantIdAndDefaultRoleTrue(final String tenantId);

    /** Every role in the realm currently flagged default — used to clear the old default when a new one is set. */
    List<UserRoles> findAllByTenantIdAndDefaultRoleTrue(final String tenantId);
}
