/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository;

import io.helixiam.authorization.domain.client.mapper.ClientProtocolMapperEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** Helix IAM (Wave 3): persistence for a client's protocol mappers ({@link ClientProtocolMapperEntity}). */
@Repository
public interface ClientProtocolMapperRepository extends JpaRepository<ClientProtocolMapperEntity, String> {

    List<ClientProtocolMapperEntity> findAllByRealmIdAndClientIdOrderByName(String realmId, String clientId);

    Optional<ClientProtocolMapperEntity> findByMapperIdAndRealmIdAndClientId(String mapperId, String realmId, String clientId);
}
