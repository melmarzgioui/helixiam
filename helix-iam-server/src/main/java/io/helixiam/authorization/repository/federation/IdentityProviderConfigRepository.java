/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.federation;

import io.helixiam.authorization.domain.federation.IdentityProviderEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Helix IAM E8.1: persistence for per-realm identity-provider configs.
 */
@Repository
public interface IdentityProviderConfigRepository extends JpaRepository<IdentityProviderEntity, String> {

    List<IdentityProviderEntity> findAllByRealmId(String realmId);

    /** The ids of a realm's configs, without loading (decrypting) them: for loading row by row. */
    @Query("select e.id from IdentityProviderEntity e where e.realmId = :realmId")
    List<String> findIdsByRealmId(@Param("realmId") String realmId);

    /** The ids of every realm's configs, without loading (decrypting) them: for loading row by row. */
    @Query("select e.id from IdentityProviderEntity e")
    List<String> findAllIds();

    Optional<IdentityProviderEntity> findByRealmIdAndAlias(String realmId, String alias);

    boolean existsByRealmIdAndAlias(String realmId, String alias);

    void deleteByRealmIdAndAlias(String realmId, String alias);

    /**
     * Bumps {@code realmId}'s identity-provider config version ({@code idp_config_version}, V78): called in the
     * transaction of every write, so a replica that sees the new version also sees the write.
     */
    @Modifying
    @Query(value = "INSERT INTO idp_config_version (realm_id, version, updated_at) VALUES (:realmId, 1, CURRENT_TIMESTAMP)"
            + " ON CONFLICT (realm_id) DO UPDATE SET version = idp_config_version.version + 1,"
            + " updated_at = CURRENT_TIMESTAMP", nativeQuery = true)
    int bumpVersion(@Param("realmId") String realmId);

    /** Every realm's identity-provider config version, as {@code [realm_id, version]} rows. */
    @Query(value = "SELECT realm_id, version FROM idp_config_version", nativeQuery = true)
    List<Object[]> findAllVersions();
}
