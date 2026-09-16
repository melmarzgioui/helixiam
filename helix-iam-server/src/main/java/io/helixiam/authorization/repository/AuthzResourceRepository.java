/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository;

import io.helixiam.authorization.domain.authz.AuthzResourceEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** Helix IAM (Wave 6): persistence for {@link AuthzResourceEntity}. */
@Repository
public interface AuthzResourceRepository extends JpaRepository<AuthzResourceEntity, String> {
    List<AuthzResourceEntity> findAllByRealmIdAndClientIdOrderByName(String realmId, String clientId);
    Optional<AuthzResourceEntity> findByRealmIdAndClientIdAndName(String realmId, String clientId, String name);
    boolean existsByRealmIdAndClientIdAndName(String realmId, String clientId, String name);
}
