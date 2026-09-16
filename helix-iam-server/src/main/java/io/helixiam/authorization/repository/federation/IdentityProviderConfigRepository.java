/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.federation;

import io.helixiam.authorization.domain.federation.IdentityProviderEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Helix IAM E8.1: persistence for per-realm identity-provider configs.
 */
@Repository
public interface IdentityProviderConfigRepository extends JpaRepository<IdentityProviderEntity, String> {

    List<IdentityProviderEntity> findAllByRealmId(String realmId);

    Optional<IdentityProviderEntity> findByRealmIdAndAlias(String realmId, String alias);

    boolean existsByRealmIdAndAlias(String realmId, String alias);

    void deleteByRealmIdAndAlias(String realmId, String alias);
}
