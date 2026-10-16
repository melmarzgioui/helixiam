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

    /** Round 6: the user's links in one realm. */
    List<FederatedLinkEntity> findAllByRealmIdAndUserId(String realmId, String userId);

    /** Round 6: every link of a realm's identity provider. */
    List<FederatedLinkEntity> findAllByRealmIdAndIdpAlias(String realmId, String idpAlias);

    /** Round 6: links whose realm the upgrade could not tell (never used for sign-in). */
    List<FederatedLinkEntity> findAllByRealmIdIsNull();

    /**
     * Task 21a: insert the link only if its {@code (alias, subject)} id is free; never overwrites. Returns the number
     * of rows inserted (0 or 1). Concurrent inserts of the same id serialise on the primary key.
     */
    @Modifying
    @Query(value = "INSERT INTO federated_link (id, realm_id, idp_alias, external_subject, user_id, created_via) "
            + "VALUES (:id, :realm, :alias, :subject, :userId, :via) ON CONFLICT DO NOTHING", nativeQuery = true)
    int insertIfAbsent(@Param("id") String id, @Param("realm") String realm, @Param("alias") String alias,
                       @Param("subject") String subject, @Param("userId") String userId, @Param("via") String via);

    /** Round 6: every link of one provenance (the start-up report of grandfathered links). */
    List<FederatedLinkEntity> findAllByCreatedVia(String createdVia);

    /** Round 6: set the provenance of {@code userId}'s links of {@code alias}; returns how many changed. */
    @Modifying
    @Query(value = "UPDATE federated_link SET created_via = :via "
            + "WHERE realm_id = :realm AND user_id = :userId AND idp_alias = :alias", nativeQuery = true)
    int updateProvenance(@Param("realm") String realm, @Param("userId") String userId, @Param("alias") String alias,
                         @Param("via") String via);

    /** Task 21a: delete a link only while {@code userId} still owns it (the stale-link replacement). */
    @Modifying
    @Query(value = "DELETE FROM federated_link WHERE id = :id AND user_id = :userId", nativeQuery = true)
    int deleteIfOwnedBy(@Param("id") String id, @Param("userId") String userId);

    /** Task 21a: the owner of a link id, read from the database (not the persistence context). */
    @Query(value = "SELECT user_id FROM federated_link WHERE id = :id", nativeQuery = true)
    Optional<String> findUserIdById(@Param("id") String id);
}
