/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.federation;

import io.helixiam.authorization.domain.federation.FederatedLinkEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** Persistence for federated-identity links ({@link FederatedLinkEntity}). */
@Repository
public interface FederatedLinkRepository extends JpaRepository<FederatedLinkEntity, String> {

    List<FederatedLinkEntity> findAllByUserId(String userId);

    /** Every link of an identity-provider alias (aliases are global; callers filter by realm). */
    List<FederatedLinkEntity> findAllByIdpAlias(String idpAlias);

    /**
     * Task 21a: insert the link only if its {@code (alias, subject)} id is free; never overwrites. Returns the number
     * of rows inserted (0 or 1). Concurrent inserts of the same id serialise on the primary key.
     */
    @Modifying
    @Query(value = "INSERT INTO federated_link (id, idp_alias, external_subject, user_id, created_via) "
            + "VALUES (:id, :alias, :subject, :userId, 'WALLET') ON CONFLICT (id) DO NOTHING", nativeQuery = true)
    int insertIfAbsent(@Param("id") String id, @Param("alias") String alias, @Param("subject") String subject,
                       @Param("userId") String userId);

    /** Task 21a: delete a link only while {@code userId} still owns it (the stale-link replacement). */
    @Modifying
    @Query(value = "DELETE FROM federated_link WHERE id = :id AND user_id = :userId", nativeQuery = true)
    int deleteIfOwnedBy(@Param("id") String id, @Param("userId") String userId);

    /** Task 21a: the owner of a link id, read from the database (not the persistence context). */
    @Query(value = "SELECT user_id FROM federated_link WHERE id = :id", nativeQuery = true)
    Optional<String> findUserIdById(@Param("id") String id);
}
