/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository;

import io.helixiam.authorization.domain.user.UserInRole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserInRoleRepository extends JpaRepository<UserInRole, String> {
    Optional<UserInRole> findByRoleIdAndUserIdAndTenantUserId(final String roleId, final String userId, final String tenantUserId);

    Optional<UserInRole> findByRoleIdAndUserId(final String roleId, final String userId);

    List<UserInRole> findAllByRoleId(final String roleId);
}
