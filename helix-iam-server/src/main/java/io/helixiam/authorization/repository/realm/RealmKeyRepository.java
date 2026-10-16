/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.realm;

import io.helixiam.authorization.domain.realm.RealmKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

/** Persistence for per-realm signing keys ({@link RealmKey}). */
@Repository
public interface RealmKeyRepository extends JpaRepository<RealmKey, String> {

    /** The current ACTIVE signing key for a realm (at most one expected). */
    Optional<RealmKey> findFirstByRealmIdAndStatusOrderByCreationDateDesc(String realmId, String status);

    /** All keys for a realm in any of the given statuses (e.g. ACTIVE + ROTATED for the JWKS). */
    List<RealmKey> findAllByRealmIdAndStatusIn(String realmId, List<String> statuses);

    /** Every key for a realm, newest first — the full lifecycle history for the admin Keys view. */
    List<RealmKey> findAllByRealmIdOrderByCreationDateDesc(String realmId);

    /** A key of this realm only: a key id of another realm is "not found". */
    Optional<RealmKey> findByKeyIdAndRealmId(String keyId, String realmId);

    /** Keys in any realm with one of the statuses (the certificate-expiry scan). */
    List<RealmKey> findAllByStatusIn(List<String> statuses);

    /** Whether this public key (Base64 SPKI) is already stored, in any realm. */
    boolean existsByPublicKey(String publicKey);

    /**
     * Claims today's certificate-expiry warning for a key: 1 for the first caller of the day (on any replica), 0
     * after that.
     */
    @Modifying
    @Transactional
    @Query("UPDATE RealmKey k SET k.expiryWarnedOn = :today WHERE k.keyId = :keyId "
            + "AND (k.expiryWarnedOn IS NULL OR k.expiryWarnedOn < :today)")
    int claimExpiryWarning(@Param("keyId") String keyId, @Param("today") LocalDate today);
}
