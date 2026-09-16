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
}
