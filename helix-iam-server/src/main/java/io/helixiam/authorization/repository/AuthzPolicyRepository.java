/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository;

import io.helixiam.authorization.domain.authz.AuthzPolicyEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** Helix IAM (Wave 6): persistence for {@link AuthzPolicyEntity}. */
@Repository
public interface AuthzPolicyRepository extends JpaRepository<AuthzPolicyEntity, String> {
    List<AuthzPolicyEntity> findAllByRealmIdAndClientIdOrderByName(String realmId, String clientId);
    Optional<AuthzPolicyEntity> findByRealmIdAndClientIdAndName(String realmId, String clientId, String name);
    boolean existsByRealmIdAndClientIdAndName(String realmId, String clientId, String name);
}
